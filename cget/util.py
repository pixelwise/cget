import click, os, sys, shutil, json, hashlib, filelock
import tarfile, zipfile
import subprocess
import requests
import shutil
from typing import List
from pathlib import Path


class cache_lock(object):
    __in_lock = False

    def __init__(self, do_lock = True):
        self.do_lock = do_lock
        self.did_lock = False
        if self.do_lock:
            self.umask = os.getenv("CGET_UMASK")
            self.cache_base_dir = mkdir(get_cache_path())

    def __enter__(self):
        if self.do_lock and not cache_lock.__in_lock:
            self.did_lock = True
            cache_lock.__in_lock = True
            if self.umask:
                self.old_umask = os.umask(int(self.umask, 8))
            self.file_lock = filelock.FileLock(os.path.join(self.cache_base_dir, "lock"))
            self.file_lock.acquire()
            mkdir(self.cache_base_dir)

    def __exit__(self, exc_type, exc_value, traceback):
        if self.did_lock:
            self.file_lock.release()
            if self.umask:
                os.umask(self.old_umask)
            self.did_lock = False
            cache_lock.__in_lock = False


def lines_of_file(path:str)->List[str]:
    with open(path, "r") as f:
        return list(f)

def lines_of_string(s:str)->List[str]:
    return list(s.splitlines())

def to_bool(value):
    x = str(value).lower()
    return x not in ("no",  "n", "false", "f", "0", "0.0", "", "none", "[]", "{}")

USE_SYMLINKS=to_bool(os.environ.get('CGET_USE_SYMLINKS', (os.name == 'posix')))
USE_CMAKE_TAR=to_bool(os.environ.get('CGET_USE_CMAKE_TAR', True))
SIGNATURE_FINGERPRINT=os.environ.get('CGET_SIGNATURE_FINGERPRINT')

__CGET_DIR__ = os.path.dirname(os.path.realpath(__file__))

def fix_cache_permissions_recursive(path):
    if os.environ.get('CGET_DIR'):
        gid = os.stat(os.environ['CGET_DIR']).st_gid
        subprocess.check_call(["chgrp", "-R", str(gid), path])
    subprocess.check_call(["chmod", "-R", "g+rw", path])


def cget_dir(*args):
    return os.path.join(__CGET_DIR__, *args)

def is_string(obj):
    return isinstance(obj, str)

def quote(s):
    return json.dumps(s)

class BuildError(Exception):
    def __init__(self, msg=None, data=None):
        self.msg = msg
        self.data = data
    def __str__(self):
        if None: return "Build failed"
        else: return self.msg

def ensure_exists(f):
    if not f:
        raise BuildError("Invalid file path")
    if not os.path.exists(f):
        raise BuildError("File does not exists: " + f)

def can(f):
    try:
        f()
        return True
    except:
        return False

def try_until(*args):
    for arg in args[:-1]:
        try:
            arg()
            return
        except:
            pass
    try:
        args[-1]()
    except:
        raise

def write_to(file, lines):
    content = list((line + "\n" for line in lines))
    if (len(content) > 0):
        with open(file, 'w') as f:
            f.writelines(content)

def mkdir(p, fix_permissions = False):
    if not os.path.exists(p):
        fix_dir = None
        if fix_permissions:
            fix_dir = p
            while not os.path.exists(os.path.dirname(fix_dir)):
                fix_dir = os.path.dirname(fix_dir)
        os.makedirs(p)
        if fix_dir is not None:
            fix_cache_permissions_recursive(fix_dir)
    return p

def mkfile(filepath, content, always_write=True):
    if not os.path.exists(filepath) or always_write:
        mkdir(Path(filepath).parent)
        write_to(filepath, content)
    return filepath

def zipdir(src_dir, tgt_file):
    print("zipping '%s' to '%s" % (src_dir, tgt_file))
    zipf = zipfile.ZipFile(tgt_file, 'w', zipfile.ZIP_DEFLATED)
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            zipf.write(
                os.path.join(root, file),
                os.path.relpath(
                    os.path.join(root, file),
                    os.path.join(src_dir)
                )
            )
    zipf.close()

def ls(p, predicate=lambda x:True):
    if os.path.exists(p):
        return (d for d in os.listdir(p) if predicate(os.path.join(p, d)))
    else:
        return []

def get_app_dir(*args):
    return os.path.join(click.get_app_dir('cget'), *args)

def get_cache_path(*args):
    cget_dir = os.getenv("CGET_DIR", os.path.join(os.path.expanduser("~"), ".cget", "cache"))
    return os.path.join(cget_dir, *args)

def adjust_path(p):
    # Prefixing path to avoid problems with long paths on windows
    if 'nt' in os.name and os.path.isabs(p) and not p.startswith("\\\\?\\"):
        return "\\\\?\\" + p
    return p

def add_cache_file(key, f):
    mkdir(get_cache_path(key))
    shutil.copy2(f, get_cache_path(key, os.path.basename(f)))

def get_cache_file(key):
    p = get_cache_path(key)
    if os.path.exists(p):
        content = list(ls(p))
        if content:
            return os.path.join(p, content[0])
    return None

def delete_dir(path):
    if path is not None and os.path.exists(path): shutil.rmtree(adjust_path(path))

def symlink_dir(src, dst):
    for root, dirs, files in os.walk(src):
        all_files = (
            file
            for x in [dirs, files]
            for file in x
            if os.path.islink(os.path.join(root, file)) or os.path.isfile(os.path.join(root, file))
        )
        for file in all_files:
            path = os.path.relpath(root, src)
            d = os.path.join(dst, path)
            mkdir(d)
            relpath = os.path.relpath(os.path.join(root, file), d)
            try:
                os.symlink(relpath, os.path.join(d, file))
            except:
                raise BuildError("Failed to link: {} -> {}".format(os.path.join(root, file), os.path.join(d, file)))

def copy_dir(src, dst):
    for root, dirs, files in os.walk(src):
        for file in files:
            path = os.path.relpath(root, src)
            d = os.path.join(dst, path)
            mkdir(d)
            src_file = os.path.join(root, file)
            shutil.copy2(adjust_path(src_file), os.path.join(d, file))

def rm_symlink(file):
    if os.path.islink(file):
        f = os.readlink(file)
        if not os.path.exists(f): os.remove(file)

def rm_symlink_in(file, prefix):
    if os.path.islink(file):
        f = os.readlink(file)
        if not os.path.isabs(f):
            f = os.path.normpath(os.path.join(os.path.dirname(file), f))
        if f.startswith(prefix):
            os.remove(file)

def rm_symlink_dir(d):
    for root, dirs, files in os.walk(d):
        for file in files:
            rm_symlink(os.path.join(root, file))

def rm_symlink_from(d, prefix):
    for root, dirs, files in os.walk(prefix):
        if not root.startswith(d):
            for file in files:
                rm_symlink_in(os.path.join(root, file), d)

def rm_dup_dir(d, prefix, remove_both=True):
    for root, dirs, files in os.walk(d):
        for file in files:
            fullpath = os.path.join(root, file)
            relpath = os.path.relpath(fullpath, d)
            if '..' in relpath:
                raise BuildError('Trying to remove link outside of prefix directory: ' + relpath)
            os.remove(os.path.join(prefix, relpath))
            if remove_both: os.remove(fullpath)

def rm_empty_dirs(d):
    has_files = False
    for x in os.listdir(d):
        p = os.path.join(d, x)
        if os.path.isdir(p) and not os.path.islink(p):
            has_files = has_files or rm_empty_dirs(p)
        else:
            has_files = True
    if not has_files: os.rmdir(d)
    return has_files

def get_dirs(d):
    return (os.path.join(d,o) for o in os.listdir(d) if os.path.isdir(os.path.join(d,o)))

def copy_to(src, dst_dir):
    target = os.path.join(dst_dir, os.path.basename(src))
    if os.path.isfile(src): shutil.copyfile(src, target)
    else: shutil.copytree(src, target)
    return target

def symlink_to(src, dst_dir):
    target = os.path.join(dst_dir, os.path.basename(src))
    os.symlink(src, target)
    return target

def download_to(url, download_dir, insecure=False):
    name = url.split('/')[-1]
    file_name = os.path.join(download_dir, name)
    file_name_tmp = file_name + ".tmp"
    click.echo("Downloading {0}".format(url))
    with open(file_name_tmp, "wb") as f:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        total_length = response.headers.get('content-length')
        if total_length is None: # no content length header
            f.write(response.content)
        else:
            total_length = int(total_length)
            with click.progressbar(length=total_length, width=70) as bar:
                for data in response.iter_content(chunk_size=4096):
                    f.write(data)
                    bar.pos += len(data)
                    bar.update(0)
                bar.update(total_length)
    if not os.path.exists(file_name_tmp):
        raise BuildError("Download failed for: {0}".format(url))
    os.rename(file_name_tmp, file_name)
    return file_name

def transfer_to(f, dst, copy=False):
    if USE_SYMLINKS and not copy: return symlink_to(f, dst)
    else: return copy_to(f, dst)

def retrieve_url(url, dst, copy=False, insecure=False, hash=None):
    remote = not url.startswith('file://')
    # Retrieve from cache
    if remote and hash:
        f = get_cache_file(hash.replace(':', '-'))
        if f: return f
    f = download_to(url, dst, insecure=insecure) if remote else transfer_to(url[7:], dst, copy=copy)
    if os.path.isfile(f) and hash:
        click.echo("Computing hash: {}".format(hash))
        hash_type, hash_value = hash.lower().split(':')
        computed = hash_file(f, hash_type)
        if computed == hash_value:
            if remote: add_cache_file(hash.replace(':', '-'), f)
        else:
            raise BuildError("Hash doesn't match for {0}: {1} != {2}".format(url, hash_type + ":" + computed, hash))
    return f

def unarchive(archive, dst):
    if archive.endswith('.zip'):
        with zipfile.ZipFile(archive,'r') as f:
            f.extractall(dst)
    elif tarfile.is_tarfile(archive):
        if USE_CMAKE_TAR:
            cmd([which('cmake'), '-E', 'tar', 'xzf', os.path.abspath(archive)], cwd=dst)
        else:
            tarfile.open(archive).extractall(dst)
    else:
        # Treat as a single source file
        d = os.path.join(dst, 'header')
        mkdir(d)
        copy_to(archive, d)

def removeprefix(s, p):
    if s.startswith(p):
        s = s[len(p):]
    return s

def archive(src, archive, base_dir = None):
    tmp = archive + ".tmp"
    arcname = None
    if base_dir is not None:
        base_dir = os.path.abspath(base_dir)
        arcname = removeprefix(os.path.abspath(src), base_dir).lstrip("/")
    print("src %s archive %s base_dir %s arcname %s" % (src, archive, base_dir, arcname))
    if archive.endswith(".tar.xz"):
        with tarfile.open(tmp, "w:xz") as f:
            f.add(src, arcname=arcname)
    elif archive.endswith(".tar.gz"):
        with tarfile.open(tmp, "w:xg") as f:
            f.add(src, arcname=arcname)
    elif archive.endswith(".tar.bz"):
        with tarfile.open(tmp, "w:bz2") as f:
            f.add(src, arcname=arcname)
    else:
        raise Exception("unsupported archive format: %s" % archive)
    os.rename(tmp, archive)

def hash_file(f, t):
    h = hashlib.new(t)
    h.update(open(f, 'rb').read())
    return h.hexdigest()

def which(p, paths=None, throws=True):
    exes = [p+x for x in ['', '.exe', '.bat']]
    for dirname in list(paths or [])+os.environ['PATH'].split(os.pathsep):
        for exe in exes:
            candidate = os.path.join(os.path.expanduser(dirname), exe)
            if os.path.isfile(candidate):
                return candidate
    if throws: raise BuildError("Can't find file %s" % p)
    else: return None

def merge(*args):
    result = {}
    for d in args:
        result.update(dict(d or {}))
    return result

def flat(*args):
    for arg in args:
        for x in arg:
            for y in x: yield y

def cmd(args, env=None, capture=None, **kwargs):
    e = merge(os.environ, env)
    c = capture or ''
    stdout = None
    stderr = None
    if c == 'out' or c == 'all': stdout = subprocess.PIPE
    if c == 'err' or c == 'all': stderr = subprocess.PIPE
    child = subprocess.Popen(args, stdout=stdout, stderr=stderr, env=e, **kwargs)
    out = child.communicate()
    if child.returncode != 0:
        raise BuildError(msg='Command failed: ' + str(args), data=e)
    return out

def as_list(x):
    if is_string(x): return [x]
    else: return list(x)

def to_define_dict(xs):
    result = {}
    for x in xs:
        if '=' in x:
            p = x.split('=')
            result[p[0]] = p[1]
        else:
            result[x] = ''
    return result

def as_dict_str(d):
    result = {}
    for x in d:
        result[x] = str(d[x])
    return result

def actual_path(path, start=None):
    if os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(start or os.getcwd(), os.path.expanduser(path)))

class Commander:
    def __init__(self, paths=None, env=None, verbose=False, arch=None):
        self.paths = paths
        self.env = env
        self.verbose = verbose
        self.arch = arch

    def _get_paths_env(self):
        if self.paths is not None:
            return { 'PATH': os.pathsep.join(list(self.paths)+[os.environ['PATH']]) }
        else: return None

    def _cmd(self, name, args=None, options=None, env=None, **kwargs):
        exe = which(name, self.paths)
        option_args = ["{0}={1}".format(key, value) for key, value in options.items()] if options else []
        c = [exe] + option_args + as_list(args or [])
        if self.arch:
            c = ["arch", "-arch", self.arch] + c
        if self.verbose: click.secho(' '.join(c), bold=True)
        return cmd(c, env=as_dict_str(merge(self.env, self._get_paths_env(), env)), **kwargs)

    def __getattr__(self, name):
        c = name.replace('_', '-')
        def f(*args, **kwargs):
            return self._cmd(c, *args, **kwargs)
        return f

    def __getitem__(self, name):
        def f(*args, **kwargs):
            return self._cmd(name, *args, **kwargs)
        return f

    def __contains__(self, name):
        exe = which(name, self.paths, throws=False)
        return exe is not None
