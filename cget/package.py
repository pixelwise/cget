import base64, copy, argparse, dirhash, hashlib, os
import cget.util as util

def encode_url(url:str):
    x = url[url.find('://')+3:].encode("utf8")
    return '_url_' + base64.urlsafe_b64encode(x).decode('utf-8').replace('=', '_')

def decode_url(url):
    s = url.replace('_', '=')[5:]
    return base64.urlsafe_b64decode(str(s)).decode('utf-8')

class PackageSource:
    def __init__(self, name=None, url=None, fname=None, recipe=None):
        self.name = name
        self.url = url
        self.fname = fname
        self.recipe = recipe

    def to_name(self):
        return self.name or self.url or self.to_fname()

    def to_fname(self):
        if self.fname is None: self.fname = self.get_encoded_name_url()
        return self.fname

    def get_encoded_name_url(self):
        if self.name is None: return encode_url(self.url)
        else: return self.name.replace('/', '__')

    def get_src_dir(self):
        if self.url.startswith('file://'):
            return self.url[7:] # Remove "file://"
        raise TypeError()

    def calc_hash(self):
        if self.recipe:
            return dirhash.dirhash(self.recipe, "sha1")
        elif self.url:
            return hashlib.sha1(self.url.encode("utf-8")).hexdigest()
        raise Exception("no url or recipe: %s" % self.__dict__)

    def dump(self):
        if self.recipe:
            data = {}
            for  dirpath, dirnames, filenames in os.walk(self.recipe):
                for filename in filenames:
                    key = os.path.join(os.path.relpath(dirpath, self.recipe), filename)
                    fullpath = os.path.join(dirpath, filename)
                    data[key] = util.lines_of_file(fullpath)
            return data
        elif self.url:
            return self.url
        raise Exception("no url or recipe: %s" % self.__dict__)

def fname_to_pkg(fname):
    if fname.startswith('_url_'): return PackageSource(name=decode_url(fname), fname=fname)
    else: return PackageSource(name=fname.replace('__', '/'), fname=fname)

class PackageBuild:
    def __init__(self, pkg_src=None, define=None, parent=None, test=False, hash=None, build=None, cmake=None, variant=None, requirements=None, file=None, patch=None, system_dependency=None):
        self.pkg_src = pkg_src
        self.define = define or []
        self.parent = parent
        self.test = test
        self.build = build
        self.hash = hash
        self.cmake = cmake
        self.variant = variant or 'Release'
        self.requirements = requirements
        self.file = file
        self.patch = patch or []
        self.system_dependencies = system_dependency or []

    def merge_defines(self, defines):
        result = copy.copy(self)
        result.define.extend(defines)
        return result

    def merge(self, other):
        result = copy.copy(self)
        if result.define: result.define.extend(other.define)
        else: result.define = other.define
        if result.patch: result.patch.extend(other.patch)
        else: result.patch = other.patch
        if result.system_dependencies: result.system_dependencies.extend(other.system_dependencies)
        else: result.system_dependencies = other.system_dependencies
        for field in dir(self):
            if not callable(getattr(self, field)) and not field.startswith("__") and not field in ['define', 'pkg_src']:
                x = getattr(self, field)
                y = getattr(other, field)
                setattr(result, field, y or x)
        return result

    def of(self, parent):
        result = copy.copy(self)
        result.parent = parent.to_fname()
        result.variant = parent.variant
        return result

    def to_fname(self):
        if isinstance(self.pkg_src, PackageSource): return self.pkg_src.to_fname()
        else: return self.pkg_src

    def to_name(self):
        if isinstance(self.pkg_src, PackageSource): return self.pkg_src.to_name()
        else: return self.pkg_src

def parse_pkg_build_tokens(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('pkg_src', nargs='?')
    parser.add_argument('-D', '--define', action='append', default=[])
    parser.add_argument('-P', '--patch', action='append', default=[])
    parser.add_argument('-S', '--system-dependency', action='append', default=[])
    parser.add_argument('-H', '--hash')
    parser.add_argument('-X', '--cmake')
    parser.add_argument('-f', '--file')
    parser.add_argument('-t', '--test', action='store_true')
    parser.add_argument('-b', '--build', action='store_true')
    return PackageBuild(**vars(parser.parse_args(args=args)))
