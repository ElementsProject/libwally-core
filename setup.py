"""setuptools config for wallycore """
from setuptools import setup, Extension
import copy, os, platform, shutil
import distutils.sysconfig
import subprocess

ABS_PATH = os.path.dirname(os.path.abspath(__file__)) + '/'
CONFIGURE_ENV = copy.deepcopy(os.environ)
DISTUTILS_ENV = distutils.sysconfig.get_config_vars()
IS_WINDOWS = platform.system() == "Windows"
ARCH_FLAGS = os.environ.get('ARCHFLAGS','').split()

def call(args, cwd=ABS_PATH):
    subprocess.check_call(args, cwd=cwd, env=CONFIGURE_ENV)

if not os.path.exists('src/secp256k1/Makefile.am'):
    # Sync libsecp-zkp
    call(['git','submodule','init'])
    call(['git','submodule','sync','--recursive'])
    call(['git','submodule','update','--init','--recursive'])

CONFIGURE_ARGS = ['--disable-shared', '--enable-static', '--with-pic',
    '--enable-swig-python', '--enable-python-manylinux',
    '--disable-swig-java', '--disable-tests', '--disable-dependency-tracking']


archs = []
while ARCH_FLAGS:
    if ARCH_FLAGS[0] == '-arch':
        archs.append(ARCH_FLAGS[1])
        ARCH_FLAGS.pop(0)
    ARCH_FLAGS.pop(0)

if os.environ.get('GITHUB_ACTION') and os.environ.get('RUNNER_OS') == 'macOS':
    # Github CI build on an macOS box
    is_x86 = os.environ.get('RUNNER_ARCH', '') == 'X64'
    is_native = not archs or (len(archs) == 1 and (is_x86 == (archs[0] == 'x86_64')))
    # TODO: Enable builds on M1 macs once github supports them
    if is_x86 and not is_native:
        # We are cross-compiling or compiling a univeral2 binary.
        # Configure our source code as a cross compile to make the build work
        CONFIGURE_ARGS += ['--host', 'x86_64-apple-darwin']
        arch = 'universal2' if len(archs) > 1 else archs[0]
        CONFIGURE_ARGS += ['--target', '{}-apple-macos'.format(arch)]
        if len(archs) > 1:
            CONFIGURE_ARGS += ['--with-asm=no']
        if 'PY_CFLAGS' in DISTUTILS_ENV:
            CONFIGURE_ENV['CFLAGS'] = DISTUTILS_ENV['PY_CFLAGS']
            CONFIGURE_ENV['LDFLAGS'] = DISTUTILS_ENV['PY_LDFLAGS']

if not IS_WINDOWS:
    # Run the autotools/make build up front to generate our sources,
    # then build using the standard Python ext module machinery.
    # (Windows requires source generation to be done separately).
    call(['./tools/cleanup.sh'])
    call(['./tools/autogen.sh'])
    call(['./configure'] + CONFIGURE_ARGS)
    call(['make', 'swig_python/swig_python_wrap.c'], ABS_PATH + 'src/')

define_macros=[
    ('SWIG_PYTHON_BUILD', None),
    ('WALLY_CORE_BUILD', None),
    ('BUILD_ELEMENTS', None),
    ]

include_dirs=[
    './',
    './src',
    './src/ccan',
    './src/secp256k1/include',
    ]

if IS_WINDOWS:
    include_dirs = ['./src/amalgamation/windows_config'] + include_dirs
    extra_compile_args = []
else:
    extra_compile_args = ['-flax-vector-conversions']

wally_ext = Extension(
    '_wallycore',
    define_macros=define_macros,
    include_dirs=include_dirs,
    extra_compile_args=extra_compile_args,
    sources=[
        'src/swig_python/swig_python_wrap.c',
        'src/amalgamation/combined.c',
        'src/amalgamation/combined_ccan.c',
        'src/amalgamation/combined_ccan2.c',
        ],
    )

kwargs = {
    'name': 'wallycore',
    'version': '0.9.2',
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

        'Programming Language :: Python :: 3',
    ],
    'keywords': 'Bitcoin wallet BIP32 BIP38 BIP39 secp256k1',
    'project_urls': {
        'Documentation': 'https://wally.readthedocs.io/en/latest',
        'Source': 'https://github.com/ElementsProject/libwally-core',
        'Tracker': 'https://github.com/ElementsProject/libwally-core/issues',
    },
    'packages': ['wallycore'],
    'package_dir': {'': 'src/swig_python'},
    'py_modules': ['wallycore'],
    'ext_modules': [wally_ext]
}
setup(**kwargs)
