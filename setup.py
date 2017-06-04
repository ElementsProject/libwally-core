"""setuptools config for wallycore """
from setuptools import setup
import os
import platform
import subprocess
from distutils.command.build_py import build_py as _build_py
from distutils.file_util import copy_file
from distutils.dir_util import mkpath


class build_py(_build_py):

    def build_libwallycore(self):
        abs_path = os.path.dirname(os.path.abspath(__file__)) + '/'

        for cmd in ('./tools/autogen.sh',
                    './configure --enable-swig-python',
                    'make'):
            subprocess.check_call(cmd.split(' '), cwd=abs_path)
        if platform.system() == 'Darwin':
            cmd = 'cp src/.libs/libwallycore.dylib src/.libs/libwallycore.so'
            subprocess.check_call(cmd.split(' '), cwd=abs_path)

        # Copy the so to the build output dir
        mkpath(self.build_lib)
        copy_file('src/.libs/libwallycore.so', self.build_lib)

    def run(self):
        # Need to override build_py to first build the c library, then
        # perform the normal python build. Overriding build_clib would be
        # more obvious but that results in setuptools trying to do build_py
        # first, which fails because the wallycore/__init__.py is created by
        # makeing the clib
        self.build_libwallycore()
        _build_py.run(self)

setup(
    name='wallycore',

    version='0.4.0',
    description='libwally Bitcoin library',
    long_description='Python bindings for the libwally Bitcoin library',
    url='https://github.com/ElementsProject/libwally-core',
    author='Jon Griffiths',
    author_email='jon_p_griffiths@yahoo.com',
    license='MIT',
    zip_safe=False,
    cmdclass={
        'build_py': build_py,
    },

    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
    ],

    keywords='Bitcoin wallet BIP32 BIP38 BIP39 secp256k1',

    packages=['wallycore'],
    package_dir={'':'src/swig_python'},
)
