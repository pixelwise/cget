import os, shutil, shlex, six, inspect, click, contextlib, uuid, sys, functools, hashlib
import distro, platform, json, subprocess
from pathlib import Path
from typing import Dict, List

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
    def __init__(self, prefix, verbose=False, build_path=None):
        self.prefix = os.path.abspath(prefix or 'cget')
        self.verbose = verbose
        self.build_path_var = build_path
        self.cmd = util.Commander(verbose=self.verbose)
        self.toolchain = self.write_cmake()
        with open(self.toolchain, "rb") as toolchain_file:
            self.toolchain_hash = hashlib.sha1(toolchain_file.read()).hexdigest()
            self.system_id = "%s-%s-%s" % (distro.id(), distro.version(), platform.architecture())
            self.log("system: %s" % self.system_id)

    def log(self, *args):
        if self.verbose: click.secho(' '.join([str(arg) for arg in args]), bold=True)

    def check(self, f, *args):
        if self.verbose and not f(*args):
            raise util.BuildError('ASSERTION FAILURE: ', ' '.join([str(arg) for arg in args]))

    def write_cmake(self, always_write=False, **kwargs):
        return util.mkfile(self.get_private_path(), 'cget.cmake', self.generate_cmake_toolchain(**kwargs), always_write=always_write)

    @returns(inspect.isgenerator)
    @util.yield_from
    def generate_cmake_toolchain(
        self,
        toolchain=None,
        cc=None,
        cxx=None,
        cflags=None,
        cxxflags=None,
        ldflags=None,
        std=None,
        defines=None
    ):
        set_ = cmake_set
        if_ = cmake_if
        else_ = cmake_else
        append_ = cmake_append
        if toolchain: yield ['include({})'.format(util.quote(os.path.abspath(toolchain)))]
        if cxx: yield set_('CMAKE_CXX_COMPILER', cxx)
        if cc: yield set_('CMAKE_C_COMPILER', cc)
        if std:
            yield if_('NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC"',
                set_('CMAKE_CXX_STD_FLAG', "-std={}".format(std))
            )
        yield if_('"${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC"',
            set_('CMAKE_CXX_ENABLE_PARALLEL_BUILD_FLAG', "/MP")
        )
        if cflags:
            yield set_('CMAKE_C_FLAGS', "$ENV{{CFLAGS}} ${{CMAKE_C_FLAGS_INIT}} {}".format(cflags or ''), cache='STRING')
        if cxxflags or std:
            yield set_('CMAKE_CXX_FLAGS', "$ENV{{CXXFLAGS}} ${{CMAKE_CXX_FLAGS_INIT}} ${{CMAKE_CXX_STD_FLAG}} {}".format(cxxflags or ''), cache='STRING')
        if ldflags:
            for link_type in ['STATIC', 'SHARED', 'MODULE', 'EXE']:
                yield set_('CMAKE_{}_LINKER_FLAGS'.format(link_type), "$ENV{{LDFLAGS}} {0}".format(ldflags), cache='STRING')
        for dkey in defines or {}:
            name, vtype, value = parse_cmake_var_type(dkey, defines[dkey])
            yield set_(name, value, cache=vtype, quote=(vtype != 'BOOL'))
        yield if_('BUILD_SHARED_LIBS',
            set_('CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS', 'ON', cache='BOOL')
        )
        yield set_('CMAKE_FIND_FRAMEWORK', 'LAST', cache='STRING')



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

    def dumps(self, pkg) -> bytes:
        return json.dumps(
            {
                "recipes" : self.dump_recipes(pkg),
                "system_id" : self.system_id,
                "toolchain" : util.lines_of_file(self.toolchain),
                "cache_path" : util.get_cache_path(),
            },
            indent = 2
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
        return hashlib.sha1(self.dumps(pkg))

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
        use_build_cache=False
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
                    use_build_cache=use_build_cache
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
        return util.get_cache_path("builds", package_name, package_hash + ".tar.xz")

    @staticmethod
    def make_signature_path(package_name, package_hash):
        return util.get_cache_path("builds", package_name, package_hash + ".sig")

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
    def archive_cached_build(package_name, package_hash):
        install_dir = CGetPrefix.make_install_dir(package_name, package_hash)
        archive_path = CGetPrefix.make_archive_path(package_name, package_hash)
        info_path = util.get_cache_path("builds", package_name, package_hash + ".info")
        manifest_path = util.get_cache_path("builds", package_name, package_hash, "manifest.json")
        if os.path.isfile(manifest_path) and os.path.isdir(install_dir):
            if not os.path.isfile(info_path):
                shutil.copy2(manifest_path, info_path)
            if not os.path.isfile(archive_path):
                util.archive(install_dir, archive_path, Path(install_dir).parent)
            util.sign_files(
                files=[info_path, archive_path],
                strings=[package_hash],
                output_path=CGetPrefix.make_signature_path(package_name, package_hash)
            )

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
        filenames = CGetPrefix.package_archive_filenames(package_hash)
        install_dir = CGetPrefix.make_install_dir(package_name, package_hash)
        base_dir = Path(install_dir).parent
        filepaths = [os.path.join(base_dir, filename) for filename in filenames]
        if not os.path.isdir(install_dir) and not all([os.path.isfile(filepath) for filepath in filepaths]):
            if not http_src.endswith("/"):
                http_src += "/"
            print("- fetching %s/%s from %s..." % (package_name, package_hash, http_src))
            urls = [http_src + "/builds/" + package_name + "/" + filename for filename in filenames]
            util.mkdir(base_dir, True)
            try:
                for url in urls:
                    util.download_to(url, base_dir)
                print("- could fetch")
                return True
            except Exception as e:
                print("- could not fetch: %s" % e)
                return False

    @staticmethod
    def publish_cached_build(package_name, package_hash, rsync_dest):
        builds_dir_rel = util.get_cache_path(".", "builds")
        archive_path = os.path.join(builds_dir_rel, package_name, package_hash + ".tar.xz")
        info_path = os.path.join(builds_dir_rel, package_name, package_hash + ".info")
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
        sync(archive_path)
        sync(info_path)

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
            use_build_cache=use_build_cache
        )
        with util.cache_lock(use_build_cache) as cache_lock:
            using_cache = False
            if use_build_cache:
                print("- using cache -")
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
                        util.mkdir(install_dir, use_build_cache)
                        self.__build(builder, pb, src_dir, install_dir, generator, test or test_all)
                        open(os.path.join(install_dir, "manifest.json"), "wb").write(self.dumps(pb))
                    if rsync_dest is not None:
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

