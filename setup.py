from setuptools import Extension, setup, sys

with open("README.md", "r") as fh:
    long_description = fh.read()

module = Extension(
        "donut",
        include_dirs=['include'],
        sources=[
            'donut.c',
            'hash.c',
            'encrypt.c',
            'format.c',
            'loader/clib.c',
            'donutmodule.c'
        ],
        extra_link_args=['-static', 'lib/aplib64.a'],
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
