import os, shutil, shlex, six, inspect, click, contextlib, uuid, sys, functools, hashlib
import distro, platform, json, subprocess
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

from cget.builder import Builder
from cget.package import fname_to_pkg
from cget.package import PackageSource
from cget.package import PackageBuild
from cget.package import parse_pkg_build_tokens
import cget.util as util
from cget.types import returns
from cget.types import params

__CGET_DIR__ = os.path.dirname(os.path.realpath(__file__))
__CGET_CMAKE_DIR__ = os.path.join(__CGET_DIR__, 'cmake')

class cget_settings_t(NamedTuple):
    cc: str
    cxx: str
    cflags: Optional[str]
    cxxflags: Optional[str]
    python: str = "python3"
    position_independent_code: bool = True
    toolchain:Optional[str] = None
    build_shared_libs:bool =False


@params(s=six.string_types)
def parse_deprecated_alias(s):
    i = s.find(':', 0, max(s.find('://'), s.find(':\\')))
    if i > 0: 
        click.echo("WARNING: Using ':' for aliases is now deprecated.")
        return s[0:i], s[i+1:]
    else: return None, s

@params(s=six.string_types)
def parse_alias(s):
    i = s.find(',')
    if i > 0: return s[0:i], s[i+1:]
    else: return parse_deprecated_alias(s)

@params(s=six.string_types)
def parse_src_name(url, default=None):
    x = url.split('@')
    p = x[0]
    # If the same name is used, then reduce to the same name
    if '/' in p:
        ps = p.split('/')
        if functools.reduce(lambda x, y: x == y, ps):
            p = ps[0]
    v = default
    if len(x) > 1: v = x[1]
    return (p, v)

def cmake_set(var, val, quote=True, cache=None, description=None):
    x = val
    if quote: x = util.quote(val)
    if cache is None or cache.lower() == 'none':
        yield "set({0} {1})".format(var, x)
    else:
        yield 'set({0} {1} CACHE {2} "{3}")'.format(var, x, cache, description or '')

def cmake_append(var, *vals, **kwargs):
    quote = True
    if 'quote' in kwargs: quote = kwargs['quote']
    x = ' '.join(vals)
    if quote: x = ' '.join([util.quote(val) for val in vals])
    yield 'list(APPEND {0} {1})'.format(var, x)

def cmake_if(cond, *args):
    yield 'if ({})'.format(cond)
    for arg in args:
        for line in arg:
            yield '    ' + line
    yield 'endif()'

def cmake_else(*args):
    yield 'else ()'
    for arg in args:
        for line in arg:
            yield '    ' + line

def parse_cmake_var_type(key, value):
    if ':' in key:
        p = key.split(':')
        return (p[0], p[1].upper(), value)
    elif value.lower() in ['on', 'off', 'true', 'false']: 
        return (key, 'BOOL', value)
    else:
        return (key, 'STRING', value)

def find_patches(patches, start):
    result = []
    for patch in patches:
        absp = util.actual_path(patch, start)
        if os.path.exists(absp):
            result.append(absp)
    return result

def find_cmake(p, start):
    if p and not os.path.isabs(p):
        absp = util.actual_path(p, start)
        if os.path.exists(absp): return absp
        else:
            x = util.cget_dir('cmake', p)
            if os.path.exists(x): return x
            elif os.path.exists(x + '.cmake'): return x + '.cmake'
    return p



PACKAGE_SOURCE_TYPES = (six.string_types, PackageSource, PackageBuild)

class CGetPrefix:
    def __init__(self, prefix, verbose=False, build_path=None, arch=None):
        self.prefix = os.path.abspath(prefix or 'cget')
        self.verbose = verbose
        self.build_path_var = build_path
        self.cmd = util.Commander(verbose=self.verbose, arch=arch)
        self.toolchain = CGetPrefix.make_toolchain_path(prefix)
        self.arch = arch
        self.system_id = "%s-%s-%s" % (distro.id(), distro.version(), platform.machine())
        self.settings = cget_settings_t(**json.load(open(CGetPrefix.make_settings_path(prefix), "r")))
        self.state = CGetPrefix.gen_state(self.settings)

    def log(self, *args):
        if self.verbose: click.secho(' '.join([str(arg) for arg in args]), bold=True)

    def check(self, f, *args):
        if self.verbose and not f(*args):
            raise util.BuildError('ASSERTION FAILURE: ', ' '.join([str(arg) for arg in args]))

    @staticmethod
    def get_compiler_version(tool_path)->str:
        version_out = subprocess.check_output(
            [tool_path, "-v"],
            stderr=subprocess.STDOUT
        ).decode("utf-8")
        lines = util.lines_of_string(version_out)
        for line in lines:
            words = line.split()
            if "version" in words:
                i = words.index("version")
                if i + 1 < len(words):
                    return " ".join(words[:i+2])
        return version_out

    @staticmethod
    def get_python_version(tool_path)->str:
        lines = util.lines_of_string(subprocess.check_output([tool_path, "--version"]).decode("utf-8"))
        for line in lines:
            parts = line.split()
            if len(parts) == 2:
                vparts = parts[1].split(".")
                return "%s.%s" % (vparts[0], vparts[1])
        raise Exception("could not determine python version")

    @staticmethod
    def gen_state(settings:cget_settings_t)->Dict:
        state = {
            "cc_version": CGetPrefix.get_compiler_version(settings.cc),
            "cxx_version": CGetPrefix.get_compiler_version(settings.cxx),
            "python_version": CGetPrefix.get_python_version(settings.python),
            "position_independent_code": settings.position_independent_code,
            "toolchain": settings.toolchain,
            "build_shared_libs": settings.build_shared_libs,
        }
        if settings.cflags:
            state["cflags"] = settings.cflags
        if settings.cxxflags:
            state["cxxflags"] = settings.cxxflags
        return state

    @staticmethod
    def make_toolchain_path(prefix:str)->str:
        return os.path.join(prefix, 'cget', 'cget.cmake')

    @staticmethod
    def make_settings_path(prefix:str)->str:
        return os.path.join(prefix, 'cget', 'settings.json')

    @staticmethod
    def make_state_path(prefix:str)->str:
        return os.path.join(prefix, 'cget', 'state.json')

    @staticmethod
    def init(prefix:str, settings:cget_settings_t, always_write=False)->None:
        util.mkfile(
            CGetPrefix.make_toolchain_path(prefix),
            CGetPrefix.generate_cmake_toolchain(settings),
            always_write=always_write
        )
        with open(CGetPrefix.make_settings_path(prefix), "w") as settings_file:
            settings_file.write(json.dumps(settings._asdict(), indent=2))
        with open(CGetPrefix.make_state_path(prefix), "w") as state_file:
            state_file.write(json.dumps(CGetPrefix.gen_state(settings), indent=2))


    @staticmethod
    @returns(inspect.isgenerator)
    @util.yield_from
    def generate_cmake_toolchain(
        settings:cget_settings_t
    ):
        if settings.toolchain: yield ['include({})'.format(util.quote(os.path.abspath(settings.toolchain)))]
        if settings.cxx: yield cmake_set('CMAKE_CXX_COMPILER', settings.cxx)
        if settings.cc: yield cmake_set('CMAKE_C_COMPILER', settings.cc)
        if settings.cflags: yield cmake_set('CMAKE_C_FLAGS', settings.cflags)
        if settings.cxxflags: yield cmake_set('CMAKE_CXX_FLAGS', settings.cxxflags)
        yield cmake_if('"${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC"',
            cmake_set('CMAKE_CXX_ENABLE_PARALLEL_BUILD_FLAG', "/MP")
        )
        defines={
           "CMAKE_POSITION_INDEPENDENT_CODE": "YES" if settings.position_independent_code else "NO",
           "BUILD_SHARED_LIBS": "YES" if settings.build_shared_libs else "NO"
        }
        if settings.python:
            defines["BOOST_PYTHON"] = settings.python
        for dkey in defines or {}:
            name, vtype, value = parse_cmake_var_type(dkey, defines[dkey])
            yield cmake_set(name, value, cache=vtype, quote=(vtype != 'BOOL'))
        yield cmake_if('BUILD_SHARED_LIBS',
            cmake_set('CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS', 'ON', cache='BOOL')
        )
        yield cmake_set('CMAKE_FIND_FRAMEWORK', 'LAST', cache='STRING')

    def get_path(self, *paths):
        return os.path.join(self.prefix, *paths)

    def get_private_path(self, *paths):
        return self.get_path('cget', *paths)

    def get_public_path(self, *paths):
        return self.get_path('etc', 'cget', *paths)

    def get_recipe_paths(self):
        return [self.get_public_path('recipes')]

    def get_builder_path(self, *paths):
        if self.build_path_var: return os.path.join(self.build_path_var, *paths)
        else: return self.get_private_path('build', *paths)

    @contextlib.contextmanager
    def create_builder(self, name, tmp=False):
        pre = ''
        if tmp: pre = 'tmp-'
        d = self.get_builder_path(pre + name)
        exists = os.path.exists(d)
        util.mkdir(d)
        yield Builder(self, d, exists)
        if tmp: shutil.rmtree(d, ignore_errors=True)

    def get_package_directory(self, *dirs):
        return self.get_private_path('pkg', *dirs)

    def get_unlink_directory(self, *dirs):
        return self.get_private_path('unlink', *dirs)

    def get_deps_directory(self, name, *dirs):
        return self.get_package_directory(name, 'deps', *dirs)

    def get_unlink_deps_directory(self, name, *dirs):
        return self.get_unlink_directory(name, 'deps', *dirs)

    def parse_src_file(self, name, url, start=None):
        f = util.actual_path(url, start)
        self.log('parse_src_file actual_path:', start, f)
        if os.path.isfile(f): return PackageSource(name=name, url='file://' + f)
        return None

    def parse_src_recipe(self, name, url):
        p, v = parse_src_name(url)
        for rpath in self.get_recipe_paths():
            rp = os.path.normcase(os.path.join(rpath, p, v or ''))
            if os.path.exists(rp):
                return PackageSource(name=name or p, recipe=rp)
        return None

    def parse_src_github(self, name, url):
        p, v = parse_src_name(url, 'HEAD')
        if '/' in p: url = 'https://github.com/{0}/archive/{1}.tar.gz'.format(p, v)
        else: url = 'https://github.com/{0}/{0}/archive/{1}.tar.gz'.format(p, v)
        if name is None: name = p
        return PackageSource(name=name, url=url)

    def gen_manifest(self, pkg) -> bytes:
        manifest = {
            "recipes" : self.dump_recipes(pkg),
            "system_id" : self.system_id,
            "state" : self.state,
            "cache_path" : util.get_cache_path(),
            "cget_version" : 2
        }
        if self.arch:
            manifest["arch"] = self.arch
        return json.dumps(
            manifest,
            indent = 2,
            sort_keys=True
        ).encode("utf-8")

    def dump_recipes(self, pkg) -> Dict:
        recipes = {}
        pkg_src = self.parse_pkg_src(pkg)
        recipes[pkg_src.to_name()] = pkg_src.dump()
        pkg_build = self.parse_pkg_build(pkg)
        if pkg_build.requirements:
            for dependency in self.from_file(pkg_build.requirements):
                dependency_dump = self.dump_recipes(dependency)
                recipes = {**recipes, **dependency_dump}
        return recipes

    def hash_pkg(self, pkg):
        return hashlib.sha1(self.gen_manifest(pkg)).hexdigest()

    @returns(PackageSource)
    @params(pkg=PACKAGE_SOURCE_TYPES)
    def parse_pkg_src(self, pkg, start=None, no_recipe=False):
        if isinstance(pkg, PackageSource): return pkg
        if isinstance(pkg, PackageBuild): return self.parse_pkg_src(pkg.pkg_src, start)
        name, url = parse_alias(pkg)
        self.log('parse_pkg_src:', name, url, pkg)
        if '://' not in url:
            return self.parse_src_file(name, url, start) or \
                (None if no_recipe else self.parse_src_recipe(name, url)) or \
                self.parse_src_github(name, url)
        return PackageSource(name=name, url=url)

    @returns(PackageBuild)
    @params(pkg=PACKAGE_SOURCE_TYPES)
    def parse_pkg_build(self, pkg, start=None, no_recipe=False):
        if isinstance(pkg, PackageBuild):
            pkg.pkg_src = self.parse_pkg_src(pkg.pkg_src, start, no_recipe)
            if pkg.pkg_src.recipe: pkg = self.from_recipe(pkg.pkg_src.recipe, pkg)
            if pkg.cmake: pkg.cmake = find_cmake(pkg.cmake, start)
            if pkg.patch: pkg.patch = find_patches(pkg.patch, start)
            return pkg
        else:
            pkg_src = self.parse_pkg_src(pkg, start, no_recipe)
            if pkg_src.recipe: return self.from_recipe(pkg_src.recipe, name=pkg_src.name)
            else: return PackageBuild(pkg_src)

    def from_recipe(self, recipe, pkg=None, name=None):
        recipe_pkg = os.path.join(recipe, "package.txt")
        util.ensure_exists(recipe_pkg)
        p = next(iter(self.from_file(recipe_pkg, no_recipe=True)))
        self.check(lambda:p.pkg_src is not None)
        requirements = os.path.join(recipe, "requirements.txt")
        if os.path.exists(requirements): p.requirements = requirements
        p.pkg_src.recipe = recipe
        # Use original name
        if pkg: p.pkg_src.name = pkg.pkg_src.name
        elif name: p.pkg_src.name = name

        if pkg: return p.merge(pkg)
        else: return p

    def from_file(self, file, url=None, no_recipe=False):
        if file is None:
            return []
        if not os.path.exists(file):
            self.log("file not found: " + file)
            return []
        start = os.path.dirname(file)
        if url is not None and url.startswith('file://'):
            start = url[7:]
        with open(file) as f:
            self.log("parse file: " + file)
            result = []
            for line in f.readlines():
                tokens = shlex.split(line, comments=True)
                if len(tokens) > 0: 
                    pb = parse_pkg_build_tokens(tokens)
                    ps = self.from_file(util.actual_path(pb.file, start), no_recipe=no_recipe) if pb.file else [self.parse_pkg_build(pb, start=start, no_recipe=no_recipe)]
                    result += ps
            return result

    def install_deps(
        self,
        pb,
        src_dir=None, 
        test=False,
        test_all=False,
        generator=None,
        insecure=False,
        use_build_cache=False,
        rsync_dest=None,
        http_src=None
    ):
        for dependent in self.get_dependents(pb, src_dir):
            testing = test or test_all
            installable = not dependent.test or dependent.test == testing
            if installable: 
                result = self.install(
                    dependent.of(pb),
                    test_all=test_all,
                    generator=generator,
                    insecure=insecure,
                    use_build_cache=use_build_cache,
                    rsync_dest=rsync_dest,
                    http_src=http_src
                )
                print(result)

    def get_dependents(self, pb, src_dir):
        if pb.requirements:
            return self.from_file(pb.requirements, pb.pkg_src.url)
        elif src_dir:
            return self.from_file(os.path.join(src_dir, 'requirements.txt'), pb.pkg_src.url)
        else:
            return []

    def get_real_install_path(self, pb):
        return os.path.realpath(self.get_package_directory(pb.to_fname(), 'install'))

    @staticmethod
    def make_archive_path(package_name, package_hash):
        return CGetPrefix.make_archive_component_path(package_name, package_hash, "tar.xz")

    @staticmethod
    def make_info_path(package_name, package_hash):
        return CGetPrefix.make_archive_component_path(package_name, package_hash, "info")

    @staticmethod
    def make_signature_path(package_name, package_hash):
        return CGetPrefix.make_archive_component_path(package_name, package_hash, "sig")

    @staticmethod
    def make_archive_component_path(package_name, package_hash, suffix):
        return util.get_cache_path(".", "builds", package_name, package_hash + "." + suffix)

    @staticmethod
    def make_install_dir(package_name, package_hash):
        return util.get_cache_path("builds", package_name, package_hash)

    @staticmethod
    def package_archive_filenames(package_hash) -> List[str]:
        return [
            package_hash + ".sig",
            package_hash + ".info",
            package_hash + ".tar.xz",
        ]

    @staticmethod
    def archive_cached_build(package_name, package_hash)->bool:
        install_dir = CGetPrefix.make_install_dir(package_name, package_hash)
        archive_path = CGetPrefix.make_archive_path(package_name, package_hash)
        info_path = util.get_cache_path("builds", package_name, package_hash + ".info")
        manifest_path = util.get_cache_path("builds", package_name, package_hash, "manifest.json")
        if os.path.isfile(manifest_path) and os.path.isdir(install_dir):
            if not os.path.isfile(info_path):
                shutil.copy2(manifest_path, info_path)
            if not os.path.isfile(archive_path):
                util.archive(install_dir, archive_path, Path(install_dir).parent)
            return True
        else:
            if not os.path.isdir(install_dir):
                print("- no install dir for %s/%s" % (package_name, package_hash))
            if not os.path.isfile(manifest_path):
                print("- no manifest for %s/%s" % (package_name, package_hash))
            return False

    @staticmethod
    def unarchive_cached_build(package_name, package_hash):
        install_dir = CGetPrefix.make_install_dir(package_name, package_hash)
        archive_path = CGetPrefix.make_archive_path(package_name, package_hash)
        if not os.path.isdir(install_dir) and os.path.isfile(archive_path):
            target = Path(install_dir).parent
            print("- unarchiving archive %s to %s -" % (install_dir, target))
            util.unarchive(archive_path, target)

    @staticmethod
    def fetch_cached_build(package_name, package_hash, http_src):
        if util.SIGNATURE_FINGERPRINT is None:
            raise Exception("require signature fingerprint for fetching")
        filenames = CGetPrefix.package_archive_filenames(package_hash)
        install_dir = CGetPrefix.make_install_dir(package_name, package_hash)
        base_dir = Path(install_dir).parent
        filepaths = [os.path.join(base_dir, filename) for filename in filenames]
        print("- checking fetch")
        if not os.path.isdir(install_dir) and not all([os.path.isfile(filepath) for filepath in filepaths]):
            if not http_src.endswith("/"):
                http_src += "/"
            print("- fetching %s/%s from %s..." % (package_name, package_hash, http_src))
            urls = [http_src + "/builds/" + package_name + "/" + filename for filename in filenames]
            util.mkdir(base_dir, True)
            try:
                for url in urls:
                    util.download_to(url, base_dir)
                signature_path = CGetPrefix.make_signature_path(package_name, package_hash)
                archive_path = CGetPrefix.make_archive_path(package_name, package_hash)
                verify_out = subprocess.check_output(
                    [
                        "gpg",
                        "--verify-options", "show-primary-uid-only",
                        "--verify", signature_path, archive_path,
                    ],
                    stderr=subprocess.STDOUT
                )
                verified = False
                for line in verify_out.splitlines():
                    line = line.decode("utf-8")
                    parts = line.split()
                    if len(parts) > 2 and parts[1] == "using":
                        fingerprint = parts[-1]
                        if fingerprint == util.SIGNATURE_FINGERPRINT:
                            verified = True
                if not verified:
                    raise Exception("could not verify %s/%s from %s..." % (package_name, package_hash, http_src))
                print("- could fetch")
                # todo: verify manifest hash and make atomic
                return True
            except Exception as e:
                print("- could not fetch: %s" % e)
                return False

    @staticmethod
    def publish_cached_build(package_name, package_hash, rsync_dest):
        builds_dir_rel = util.get_cache_path(".", "builds")
        archive_path = CGetPrefix.make_archive_path(package_name, package_hash)
        info_path = CGetPrefix.make_info_path(package_name, package_hash)
        signature_path = CGetPrefix.make_signature_path(package_name, package_hash)
        if util.SIGNATURE_FINGERPRINT is None:
            raise Exception("require signature fingerprint for publication")
        subprocess.check_call([
            "gpg", "--yes", "--detach-sign",
            "--local-user", util.SIGNATURE_FINGERPRINT,
            "--out", signature_path,
            "--sign", archive_path
        ])
        print("- publishing %s/%s to %s..." % (package_name, package_hash, rsync_dest))
        def sync(path):
            if os.path.isfile(path):
                cmd = [
                    "rsync",
                    "-a",
                    "--relative",
                    path,
                    rsync_dest
                ]
                subprocess.check_call(cmd)
        sync(info_path)
        sync(signature_path)
        sync(archive_path)

    @returns(six.string_types)
    @params(pb=PACKAGE_SOURCE_TYPES, test=bool, test_all=bool, update=bool)
    def install(
        self,
        pb,
        test=False,
        test_all=False,
        generator=None,
        insecure=False,
        use_build_cache=False,
        rsync_dest=None,
        http_src=None
    ):
        pb = self.parse_pkg_build(pb)
        pkg_dir = self.get_package_directory(pb.to_fname())
        unlink_dir = self.get_unlink_directory(pb.to_fname())
        package_hash = self.hash_pkg(pb)
        print("=> installing %s hash %s" % (pb.to_name(), package_hash))
        self.log("package %s hash %s" % (pb.to_name(), package_hash))
        pkg_install_dir = self.get_package_directory(pb.to_fname(), 'install')
        if os.path.exists(pkg_install_dir):
            return "package %s already installed" % pb.to_name()
        if use_build_cache:
            install_dir = util.get_cache_path("builds", pb.to_name(), package_hash)
            util.mkdir(pkg_dir)
            self.log("using cached install dir '%s'" % install_dir)
        else:
            install_dir = pkg_install_dir
            self.log("using local install dir '%s'" % install_dir)
        self.install_deps(
            pb,
            test=test,
            test_all=test_all,
            generator=generator,
            insecure=insecure,
            use_build_cache=use_build_cache,
            rsync_dest=rsync_dest,
            http_src=http_src
        )
        with util.cache_lock(use_build_cache) as cache_lock:
            using_cache = False
            if use_build_cache:
                print("- using cache %s -" % http_src)
                if http_src is not None:
                    self.fetch_cached_build(pb.to_name(), package_hash, http_src)
                self.unarchive_cached_build(pb.to_name(), package_hash)
                if os.path.exists(install_dir):
                    print("=> retreived Package {} from cache".format(pb.to_name()))
                    using_cache = True
            if not using_cache:
                print("=> building %s to %s" % (pb.to_name(), install_dir))
                try:
                    with self.create_builder(pb.to_name() + "-" + uuid.uuid4().hex, tmp=True) as builder:
                        src_dir = builder.fetch(pb.pkg_src.url, pb.hash, (pb.cmake != None), insecure=insecure)
                        builder.apply_patches(src_dir=src_dir, patches=pb.patch)
                        util.mkdir(install_dir, use_build_cache)
                        self.__build(builder, pb, src_dir, install_dir, generator, test or test_all)
                        open(os.path.join(install_dir, "manifest.json"), "wb").write(self.gen_manifest(pb))
                    if rsync_dest and util.SIGNATURE_FINGERPRINT:
                        self.archive_cached_build(pb.to_name(), package_hash)
                        self.publish_cached_build(pb.to_name(), package_hash, rsync_dest)
                except:
                    shutil.rmtree(install_dir)
                    raise
            os.symlink(install_dir, pkg_install_dir)
        return "Successfully installed {}".format(pb.to_name())

    def __build(self, builder, pb, src_dir, install_dir, generator, test):
        if pb.cmake:
            target = os.path.join(src_dir, 'CMakeLists.txt')
            if os.path.exists(target):
                os.rename(target, os.path.join(src_dir, builder.cmake_original_file))
            shutil.copyfile(pb.cmake, target)
        dependents = self.get_dependents(pb, src_dir)
        dep_install_paths = list([self.get_real_install_path(dep) for dep in dependents])
        defines = (
            list(pb.define or []) +
            [
                "CMAKE_PREFIX_PATH=%s" % ";".join(
                    ['%s' % path for path in dep_install_paths + [self.prefix]]
                )
            ] +
            list([
                "CGET_%s_INSTALL_DIR=%s" % (dep.to_name(), self.get_real_install_path(dep)) for dep in dependents
            ])
        )
        pkg_config_paths = list(
            filter(
                os.path.exists,
                sum(
                    [
                        [
                            os.path.join(path, "lib/pkgconfig"),
                            os.path.join(path, "lib64/pkgconfig"),
                            os.path.join(path, "share/pkgconfig"),
                        ]
                        for path in dep_install_paths
                    ],
                    []
                )
            )
        )
        bin_paths = list(
            filter(
                os.path.exists,
                [
                    os.path.join(path, "bin")
                    for path in dep_install_paths
                ]
            )
        ) + os.getenv("PATH", "").split(":")
        configure_env = {
            "PKG_CONFIG_LIBDIR":"/dev/null",
            "PKG_CONFIG_PATH":":".join(pkg_config_paths),
            "PATH":":".join(bin_paths),
            "CFLAGS" : os.getenv("CFLAGS", ""),
            "CXXFLAGS" : os.getenv("CXXFLAGS", "")
        }
        build_env = {
            "PATH":":".join(bin_paths)
        }
        print("dependencies")
        print([dep.to_name() for dep in dependents])
        print("defines")
        print(defines)
        print("env")
        print(configure_env)
        print("build env")
        print(build_env)
        builder.configure(
            src_dir,
            defines=defines,
            generator=generator,
            install_prefix=install_dir,
            test=test,
            variant=pb.variant,
            env=configure_env
        )
        builder.build(variant=pb.variant, env=build_env)
        if test:
            builder.test(variant=pb.variant)
        builder.build(target='install', variant=pb.variant, env=build_env)

    def _list_files(self, pkg=None, top=True):
        if pkg is None:
            return util.ls(self.get_package_directory(), os.path.isdir)
        else:
            p = self.parse_pkg_src(pkg)
            ls = util.ls(self.get_deps_directory(p.to_fname()), os.path.isfile)
            if top: return [p.to_fname()]+list(ls)
            else: return ls

    def list(self, pkg=None, recursive=False, top=True):
        for d in self._list_files(pkg, top):
            p = fname_to_pkg(d)
            if os.path.exists(self.get_package_directory(d)): yield p
            if recursive:
                for child in self.list(p, recursive=recursive, top=False):
                    yield child

    def clean(self):
        if util.USE_SYMLINKS:
            util.delete_dir(self.get_private_path())
            util.rm_symlink_dir(self.prefix)
            util.rm_empty_dirs(self.prefix)
        else:
            for p in self.list():
                self.remove(p)
            util.delete_dir(self.get_private_path())

    def clean_cache(self):
        p = util.get_cache_path()
        if os.path.exists(p): shutil.rmtree(util.get_cache_path())

    def pkg_config_path(self):
        libs = []
        for p in ['lib', 'lib64', 'share']:
            libs.append(self.get_path(p, 'pkgconfig'))
        return os.pathsep.join(libs)

    @contextlib.contextmanager
    def try_(self, msg=None, on_fail=None):
        try:
            yield
        except util.BuildError as err:
            if err.msg: click.echo(err.msg)
            if msg: click.echo(msg)
            if on_fail: on_fail()
            if self.verbose: 
                if err.data: click.echo(err.data)
                raise
            sys.exit(1)
        except:
            extype, exvalue, extraceback = sys.exc_info()
            click.echo("Unexpected error: " + str(extype))
            click.echo(str(exvalue))
            if msg: click.echo(msg)
            if on_fail: on_fail()
            if self.verbose: raise
            sys.exit(1)

