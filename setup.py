"""setuptools config for wallycore """

kwargs = {
    'name': 'wallycore',
    'version': '0.8.3',
    'description': 'libwally Bitcoin library',
    'long_description': 'Python bindings for the libwally Bitcoin library',
    'url': 'https://github.com/ElementsProject/libwally-core',
    'author': 'Jon Griffiths',
    'author_email': 'jon_p_griffiths@yahoo.com',
    'license': 'MIT',
    'zip_safe': False,

    'classifiers': [
        'Development Status :: 5 - Production/Stable',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],

    'keywords': 'Bitcoin wallet BIP32 BIP38 BIP39 secp256k1',
    'project_urls': {
        'Documentation': 'https://wally.readthedocs.io/en/latest',
        'Source': 'https://github.com/ElementsProject/libwally-core',
        'Tracker': 'https://github.com/ElementsProject/libwally-core/issues',
    },

    'packages': ['wallycore'],
    'package_dir': {'':'src/swig_python'},
}

import platform
if platform.system() == "Windows":
    # On windows wally is defined as a standard python extension
    from distutils.core import Extension

    wally_ext = Extension(
        '_wallycore',
        define_macros=[
            ('SWIG_PYTHON_BUILD', None),
            ('USE_ECMULT_STATIC_PRECOMPUTATION', None),
            ('ECMULT_WINDOW_SIZE', 16),
            ('WALLY_CORE_BUILD', None),
            ('HAVE_CONFIG_H', None),
            ('SECP256K1_BUILD', None),
            ('BUILD_ELEMENTS', None),
            ],
        include_dirs=[
            # Borrowing config from wrap_js
            # TODO: Move this to another directory
            './src/wrap_js/windows_config',
            './',
            './src',
            './include',
            './src/ccan',
            './src/secp256k1',
            './src/secp256k1/src/',
            ],
        sources=[
            'src/swig_python/swig_wrap.c',
            'src/wrap_js/src/combined.c',
            'src/wrap_js/src/combined_ccan.c',
            'src/wrap_js/src/combined_ccan2.c',
            ],
    )
    kwargs['py_modules'] = ['wallycore']
    kwargs['ext_modules'] = [wally_ext]
else:
    # *nix uses a custom autotools/make build
    import distutils
    import distutils.command.build_py
    import os
    import subprocess
    import multiprocessing

    class _build_py(distutils.command.build_py.build_py):

        def build_libwallycore(self):
            abs_path = os.path.dirname(os.path.abspath(__file__)) + '/'

            def call(cmd):
                subprocess.check_call(cmd.split(' '), cwd=abs_path)

            # Run the autotools/make build to generate a python extension module
            call('./tools/cleanup.sh')
            call('./tools/autogen.sh')
            call('./configure --enable-swig-python --enable-python-manylinux --enable-ecmult-static-precomputation --enable-elements --disable-tests')
            call('make -j{}'.format(multiprocessing.cpu_count()))

            # Copy the so that has just been built to the build_dir that distutils expects it to be in
            # The extension of the built lib is dylib on osx
            so_ext = 'dylib' if platform.system() == 'Darwin' else 'so'
            src_so = 'src/.libs/libwallycore.{}'.format(so_ext)
            distutils.dir_util.mkpath(self.build_lib)
            dest_so = os.path.join(self.build_lib, 'libwallycore.so')
            distutils.file_util.copy_file(src_so, dest_so)

        def run(self):
            # Override build_py to first build the c library, then perform the normal python build.
            # Overriding build_clib would be more obvious but that results in setuptools trying to do
            # build_py first, which fails because the wallycore/__init__.py is created by making the
            # clib
            self.build_libwallycore()
            distutils.command.build_py.build_py.run(self)

    kwargs['cmdclass'] = {'build_py': _build_py}

    # Force Distribution to have ext modules. This is necessary to generate the correct platform
    # dependent filename when generating wheels because the building of the underlying wally c libs
    # is effectively hidden from distutils - which means it assumes it is building a pure python
    # module.
    from distutils.dist import Distribution
    Distribution.has_ext_modules = lambda self: True

from setuptools import setup
setup(**kwargs)
