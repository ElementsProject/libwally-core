from setuptools import setup
from cmake_build_extension import BuildExtension, CMakeExtension, GitSdistFolder, GitSdistTree
import os


def get_init_content():
    fname = os.path.join(os.getcwd(), 'init.py_in')
    if not os.path.exists(fname):
        fname = os.path.join(os.getcwd(), 'bindings', 'python', 'init.py_in')
    with open(fname, 'r') as file:
        return file.read()


setup(
    ext_modules=[
        CMakeExtension(
            name='bindings',
            install_prefix='wallycore',
            source_dir="../..",
            cmake_configure_options=[
                '-DBUILD_SHARED_LIBS=OFF',
                '-DENABLE_TESTS=OFF',
                '-DCALL_FROM_SETUP_PY=ON',
            ],
            cmake_build_type='Release',
            cmake_component="bindings",
            write_top_level_init=get_init_content(),
            disable_editable=True,
        ),
    ],
    cmdclass={
        'build_ext': BuildExtension,
        'sdist': GitSdistFolder,
    },
)
