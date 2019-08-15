from setuptools import Extension, setup

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
     name='donut',
     version='0.9.1',
     description='Donut Python C extension',
     url='https://github.com/TheWover/donut',
     author='TheWover, Odzhan, byt3bl33d3r',
     include_package_data=True,
     zip_safe=True,
     ext_modules=[module]
)
