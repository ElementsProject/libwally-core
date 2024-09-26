"""setuptools config for wallycore """
from setuptools import setup, Extension
import copy, os, platform, shutil, subprocess, sys
import distutils.sysconfig

def _msg(s):
    print(s + '\n', file=sys.stderr)

ABS_PATH = os.path.dirname(os.path.abspath(__file__)) + '/'
CONFIGURE_ENV = copy.deepcopy(os.environ)
DISTUTILS_ENV = distutils.sysconfig.get_config_vars()
IS_WINDOWS = platform.system() == "Windows"
ARCH_FLAGS = os.environ.get('ARCHFLAGS', '').split()
USE_LIB = os.environ.get('WALLY_ABI_PY_WHEEL_USE_LIB', 'no')

if USE_LIB not in ('no', 'static', 'shared'):
    _msg('Warning: WALLY_ABI_PY_WHEEL_USE_LIB has unsupported value; assuming "no".')
    USE_LIB = 'no'
if USE_LIB != 'no' and IS_WINDOWS:
    _msg('Error: WALLY_ABI_PY_WHEEL_USE_LIB is unsupported on Windows.')
    sys.exit(1)
if USE_LIB != 'shared' and (os.path.exists('src/.libs/libwallycore.so') or
                            os.path.exists('src/.libs/libwallycore.dylib')):
    _msg('Warning: libwallycore shared library has been found, but Python module will not\n'
         'use it. Set WALLY_ABI_PY_WHEEL_USE_LIB=shared to link with the shared library.')
elif USE_LIB != 'static' and os.path.exists('src/.libs/libwallycore.a'):
    _msg('Warning: libwallycore static library has been found, but Python module will not\n'
         'use it. Set WALLY_ABI_PY_WHEEL_USE_LIB=static to link with the static library.')

def _get_system_pkg(name, default_pkg):
    pkg = os.environ.get('WALLY_ABI_PY_WHEEL_USE_PKG_' + name, '')
    if pkg.lower() in ('0', 'n', 'no', 'f', 'false', 'off'):
        return ''
    if pkg.lower() in ('1', 'y', 'yes', 't', 'true', 'on'):
        return default_pkg
    return pkg

PKG_SECP256K1 = _get_system_pkg('SECP256K1', 'libsecp256k1_zkp')
if PKG_SECP256K1 and USE_LIB == 'no':
    _msg('Warning: WALLY_ABI_PY_WHEEL_USE_PKG_SECP256K1 has no effect when'
         '\nWALLY_ABI_PY_WHEEL_USE_LIB=no or is unset.')
    PKG_SECP256K1 = ''

if PKG_SECP256K1:
    try:
        import pkgconfig
    except ImportError:
        _msg('Error: WALLY_ABI_PY_WHEEL_USE_PKG_SECP256K1 requires the pkgconfig Python module.')
        sys.exit(127)

def _call(args, cwd=ABS_PATH):
    subprocess.check_call(args, cwd=cwd, env=CONFIGURE_ENV)

if (USE_LIB == 'no' or not PKG_SECP256K1) and not os.path.exists('src/secp256k1/Makefile.am'):
    # Sync libsecp256k1-zkp (only if needed)
    _call(['git', 'submodule', 'init'])
    _call(['git', 'submodule', 'sync', '--recursive'])
    _call(['git', 'submodule', 'update', '--init', '--recursive'])

CONFIGURE_ARGS = [
    '--with-pic', '--enable-swig-python', '--enable-python-manylinux',
    '--disable-swig-java', '--disable-tests', '--disable-dependency-tracking'
]

if USE_LIB == 'shared':
    CONFIGURE_ARGS += ['--enable-shared', '--disable-static']
else:
    CONFIGURE_ARGS += ['--disable-shared', '--enable-static']

if PKG_SECP256K1:
    CONFIGURE_ARGS += ['--with-system-secp256k1=' + PKG_SECP256K1]


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

if not IS_WINDOWS and (USE_LIB == 'no' or not os.path.exists('src/Makefile')):
    # Run the autotools/make build up front to generate our sources,
    # then build using the standard Python ext module machinery.
    # (Windows requires source generation to be done separately).
    _call(['./tools/cleanup.sh'])
    _call(['./tools/autogen.sh'])
    _call(['./configure'] + CONFIGURE_ARGS)
    if USE_LIB == 'no':
        _call(['make', 'swig_python/swig_python_wrap.c'], ABS_PATH + 'src/')
    else:
        _call(['make'])

define_macros = [
    ('SWIG_PYTHON_BUILD', None),
    ('WALLY_CORE_BUILD', None),
    ('BUILD_ELEMENTS', None),
]

include_dirs = [
    './',
    './src',
]
library_dirs = []
libraries = []
sources = ['src/swig_python/swig_python_wrap.c']

if USE_LIB == 'no':
    # Compile the amalgamated sources to build the wheel (default)
    include_dirs += [
        './src/ccan',
        './src/secp256k1/include',
    ]
    sources += [
        'src/amalgamation/combined.c',
        'src/amalgamation/combined_ccan.c',
        'src/amalgamation/combined_ccan2.c',
    ]
else:
    # Compile the swig python wrapper file and link it with wally/secp
    # to build the wheel.
    if PKG_SECP256K1:
        # Link with a system installed secp
        secp256k1 = pkgconfig.parse(PKG_SECP256K1)
        include_dirs += secp256k1['include_dirs']
    else:
        # Link with the in-tree secp256k1-zkp
        include_dirs += ['./src/secp256k1/include']
    library_dirs += ['src/.libs']
    libraries += ['wallycore']
    if USE_LIB == 'static':
        if PKG_SECP256K1:
            library_dirs += secp256k1['library_dirs']
            libraries += secp256k1['libraries']
        else:
            library_dirs += ['src/secp256k1/.libs']
            libraries += ['secp256k1']

if IS_WINDOWS:
    include_dirs = ['./src/amalgamation/windows_config'] + include_dirs
    extra_compile_args = []
else:
    extra_compile_args = ['-flax-vector-conversions']

wally_ext = Extension(
    '_wallycore',
    define_macros=define_macros,
    include_dirs=include_dirs,
    library_dirs=library_dirs,
    libraries=libraries,
    extra_compile_args=extra_compile_args,
    sources=sources,
)

kwargs = {
    'name': 'wallycore',
    'version': '1.3.1',
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
    'keywords': 'Bitcoin wallet BIP32 BIP38 BIP39 secp256k1 Blockstream Liquid Elements',
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
