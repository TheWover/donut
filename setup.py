from setuptools import Extension, setup
import sys

with open("README.md", "r") as fh:
    long_description = fh.read()

static_libraries   = ['aplib64']
static_lib_dir     = 'lib'
libraries          = []
library_dirs       = ['lib']
extra_compile_args = []
extra_link_args    = []
extra_objects      = []
include_dirs       = ['include']
sources            = ['donut.c', 
                      'hash.c', 
                      'encrypt.c', 
                      'format.c', 
                      'loader/clib.c', 
                      'donutmodule.c']

if sys.platform == 'win32':
    libraries.extend(static_libraries)
    library_dirs.append(static_lib_dir)
    extra_objects = []
elif sys.platform == 'win64':
    libraries.extend(static_libraries)
    library_dirs.append(static_lib_dir)
    extra_objects = []    
else: # POSIX
    extra_objects = ['{}/{}.a'.format(static_lib_dir, l) for l in static_libraries]


module = Extension(
        "donut",
        include_dirs       = include_dirs,
        sources            = sources,
        libraries          = libraries,
        library_dirs       = library_dirs,
        extra_compile_args = extra_compile_args,
        extra_link_args    = extra_link_args,
        extra_objects      = extra_objects,
)

setup(
     name='donut-shellcode',
     version='0.9.3',
     description='Donut Python C extension',
     long_description=long_description,
     long_description_content_type="text/markdown",
     url='https://github.com/TheWover/donut',
     author='TheWover, Odzhan, byt3bl33d3r',
     include_package_data=True,
     zip_safe=True,
     ext_modules=[module],
     python_requires='>=3.0',
)
