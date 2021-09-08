import subprocess
import click, os, functools, sys

from cget import __version__
from cget.prefix import CGetPrefix
from cget.prefix import PackageBuild
from concurrent.futures import ThreadPoolExecutor
import cget.util as util


aliases = {
    'rm': 'remove',
    'ls': 'list'
}

class AliasedGroup(click.Group):
    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        if cmd_name in aliases:
            return click.Group.get_command(self, ctx, aliases[cmd_name])
        return None


@click.group(cls=AliasedGroup, context_settings={'help_option_names': ['-h', '--help']})
@click.version_option(version=__version__, prog_name='cget')
@click.option('-p', '--prefix', envvar='CGET_PREFIX', help='Set prefix used to install packages')
@click.option('-v', '--verbose', is_flag=True, envvar='VERBOSE', help="Enable verbose mode")
@click.option('-B', '--build-path', envvar='CGET_BUILD_PATH', help='Set the path for the build directory to use when building the package')
@click.pass_context
def cli(ctx, prefix, verbose, build_path):
    ctx.obj = {}
    if prefix: ctx.obj['PREFIX'] = prefix
    if verbose: ctx.obj['VERBOSE'] = verbose
    if build_path: ctx.obj['BUILD_PATH'] = build_path

def use_prefix(f):
    @click.option('-p', '--prefix', help='Set prefix used to install packages')
    @click.option('-v', '--verbose', is_flag=True, help="Enable verbose mode")
    @click.option('-B', '--build-path', help='Set the path for the build directory to use when building the package')
    @click.pass_obj
    @functools.wraps(f)
    def w(obj, prefix, verbose, build_path, *args, **kwargs):
        p = CGetPrefix(prefix or obj.get('PREFIX'), verbose or obj.get('VERBOSE'), build_path or obj.get('BUILD_PATH'))
        f(p, *args, **kwargs)
    return w

@cli.command(name='init')
@use_prefix
@click.option('-t', '--toolchain', required=False, help="Set cmake toolchain file to use")
@click.option('--cc', required=False, help="Set c compiler")
@click.option('--cxx', required=False, help="Set c++ compiler")
@click.option('--cflags', required=False, help="Set additional c flags")
@click.option('--cxxflags', required=False, help="Set additional c++ flags")
@click.option('--ldflags', required=False, help="Set additional linker flags")
@click.option('--std', required=False, help="Set C++ standard if available")
@click.option('-D', '--define', multiple=True, help="Extra configuration variables to pass to CMake")
@click.option('--shared', is_flag=True, help="Set toolchain to build shared libraries by default")
@click.option('--static', is_flag=True, help="Set toolchain to build static libraries by default")
def init_command(prefix, toolchain, cc, cxx, cflags, cxxflags, ldflags, std, define, shared, static):
    """ Initialize install directory """
    if shared and static:
        click.echo("ERROR: shared and static are not supported together")
        sys.exit(1)
    defines = util.to_define_dict(define)
    if shared: defines['BUILD_SHARED_LIBS'] = 'On'
    if static: defines['BUILD_SHARED_LIBS'] = 'Off'
    prefix.write_cmake(
        always_write=True, 
        toolchain=toolchain, 
        cc=cc,
        cxx=cxx,
        cflags=cflags, 
        cxxflags=cxxflags, 
        ldflags=ldflags, 
        std=std, 
        defines=defines
    )

def is_hash(s):
    if len(s) != 40:
        return False
    allowed_chars = set("abcdef0123456789ABCDEF")
    if len(set(s) - allowed_chars) > 0:
        return False
    return True

def find_cached_builds(builds_dir, subdir=None):
    startdir = builds_dir
    if subdir is not None:
        startdir = os.path.join(builds_dir, subdir)
    for entry in os.listdir(startdir):
        entry_path = os.path.join(startdir, entry)
        if os.path.isdir(entry_path):
            next_subdir = entry
            if subdir is not None:
                next_subdir = os.path.join(subdir, entry)
            if is_hash(entry):
                yield subdir, entry
            else:
                yield from find_cached_builds(builds_dir, next_subdir)


@cli.command(name='archive_all')
@click.option('-n', '--num-threads', default=4, help="number of threads")
def archive_all(num_threads):
    builds_dir = util.get_cache_path("builds")
    executor = ThreadPoolExecutor(num_threads)
    def execute(item):
        package_name, package_hash = item
        print("archiving %s/%s..." % (package_name, package_hash))
        CGetPrefix.archive_cached_build(package_name, package_hash)
    executor.map(execute, find_cached_builds(builds_dir))
    executor.shutdown()
    print("done!")


@cli.command(name='publish_all')
@click.option('-d', '--dest', required=True, help="rsync destination")
def publish_all(dest):
    builds_dir = util.get_cache_path("builds")
    for package_name, package_hash in find_cached_builds(builds_dir):
        CGetPrefix.publish_cached_build(package_name, package_hash, dest)
    print("done!")


@cli.command(name='install')
@use_prefix
@click.option('-t', '--test', is_flag=True, help="Test package before installing by running ctest or check target")
@click.option('--test-all', is_flag=True, help="Test all packages including its dependencies before installing by running ctest or check target")
@click.option('-f', '--file', default=None, help="Install packages listed in the file")
@click.option('-D', '--define', multiple=True, help="Extra configuration variables to pass to CMake")
@click.option('-G', '--generator', envvar='CGET_GENERATOR', help='Set the generator for CMake to use')
@click.option('-X', '--cmake', help='Set cmake file to use to build project')
@click.option('--http-src', is_flag=False, envvar='CGET_HTTP_SRC', help="http source to fetch builds from")
@click.option('--rsync-dst', is_flag=False, envvar='CGET_RSYNC_DST', help="rsync destination to push builds to")
@click.option('--debug', is_flag=True, help="Install debug version")
@click.option('--release', is_flag=True, help="Install release version")
@click.option('--insecure', is_flag=True, help="Don't use https urls")
@click.option('--use-build-cache', is_flag=True, help="Cache builds")
@click.argument('pkgs', nargs=-1, type=click.STRING)
def install_command(prefix, pkgs, define, file, test, test_all, generator, cmake, debug, release, insecure, use_build_cache, http_src, rsync_dst):
    """ Install packages """
    if debug and release:
        click.echo("ERROR: debug and release are not supported together")
        sys.exit(1)
    variant = 'Release'
    if debug: variant = 'Debug'
    if not file and not pkgs:
        if os.path.exists('dev-requirements.txt'): file = 'dev-requirements.txt'
        else: file = 'requirements.txt'
    pbs = [PackageBuild(pkg, cmake=cmake, variant=variant) for pkg in pkgs]
    for pbu in util.flat([prefix.from_file(file), pbs]):
        pb = pbu.merge_defines(define)
        with prefix.try_("Failed to build package {}".format(pb.to_name()), on_fail=lambda: prefix.remove(pb)):
            click.echo(prefix.install(
                pb,
                test=test,
                test_all=test_all,
                generator=generator,
                insecure=insecure,
                use_build_cache=use_build_cache,
                http_src=http_src,
                rsync_dst=rsync_dst
            ))

if __name__ == '__main__':
    cli()

