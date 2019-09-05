from setuptools import Extension, setup

with open("README.md", "r") as fh:
    long_description = fh.read()

module = Extension(
        "donut",
        include_dirs=[
            'include'
        ],
        sources=[
            'donut.c',
            'hash.c',
            'encrypt.c',
            'payload/clib.c',
            'donutmodule.c'
        ]
)

setup(
     name='donut-shellcode',
     version='0.9.2',
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
