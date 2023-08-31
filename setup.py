"""setuptools config for wallycore """
from setuptools import setup, Extension
import copy, os, platform, shutil
import distutils.sysconfig

CONFIGURE_ARGS = '--enable-swig-python --enable-python-manylinux --enable-elements'
CONFIGURE_ARGS += ' --disable-swig-java --disable-tests --disable-dependency-tracking'

distutils_env = distutils.sysconfig.get_config_vars()
configure_env = copy.deepcopy(os.environ)

is_windows = platform.system() == "Windows"
arch_flags = os.environ.get('ARCHFLAGS','').split()
archs = []
while arch_flags:
    if arch_flags[0] == '-arch':
        archs.append(arch_flags[1])
        arch_flags.pop(0)
    arch_flags.pop(0)

if os.environ.get('GITHUB_ACTION') and os.environ.get('RUNNER_OS') == 'macOS':
    # Github CI build on an macOS box
    is_x86 = os.environ.get('RUNNER_ARCH', '') == 'X64'
    is_native = not archs or (len(archs) == 1 and (is_x86 == (archs[0] == 'x86_64')))
    # TODO: Enable builds on M1 macs once github supports them
    if is_x86 and not is_native:
        # We are cross-compiling or compiling a univeral2 binary.
        # Configure our source code as a cross compile to make the build work
        CONFIGURE_ARGS += ' --host x86_64-apple-darwin'
        arch = 'universal2' if len(archs) > 1 else archs[0]
        CONFIGURE_ARGS += ' --target {}-apple-macos'.format(arch)
        if len(archs) > 1:
            CONFIGURE_ARGS += ' --with-asm=no'
        if 'PY_CFLAGS' in distutils_env:
            configure_env['CFLAGS'] = distutils_env['PY_CFLAGS']
            configure_env['LDFLAGS'] = distutils_env['PY_LDFLAGS']

if not is_windows:
    # Run the autotools/make build up front to generate our sources,
    # then build using the standard Python ext module machinery.
    # (Windows requires source generation to be done separately).
    import multiprocessing
    import os
    import subprocess

    abs_path = os.path.dirname(os.path.abspath(__file__)) + '/'

    def call(cmd):
        subprocess.check_call(cmd.split(' '), cwd=abs_path, env=configure_env)

    call('./tools/cleanup.sh')
    call('./tools/autogen.sh')
    call('./configure {}'.format(CONFIGURE_ARGS))
    call('make -j{}'.format(multiprocessing.cpu_count()))

define_macros=[
    ('SWIG_PYTHON_BUILD', None),
    ('WALLY_CORE_BUILD', None),
    ('HAVE_CONFIG_H', None),
    ('SECP256K1_BUILD', None),
    ('BUILD_ELEMENTS', None)
    ]
if is_windows:
    define_macros.append(('USE_ECMULT_STATIC_PRECOMPUTATION', None))
    define_macros.append(('ECMULT_WINDOW_SIZE', 15))

include_dirs=[
    './',
    './src',
    './include',
    './src/ccan',
    './src/secp256k1',
    './src/secp256k1/src/'
    ]
if is_windows:
    shutil.copyfile('./src/amalgamation/windows_config/libsecp256k1-config.h', 'src/secp256k1/src/libsecp256k1-config.h')
    include_dirs = ['./src/amalgamation/windows_config'] + include_dirs

extra_compile_args = ['-flax-vector-conversions']

wally_ext = Extension(
    '_wallycore',
    define_macros=define_macros,
    include_dirs=include_dirs,
    extra_compile_args=extra_compile_args,
    sources=[
        'src/swig_python/swig_wrap.c' if is_windows else 'src/swig_python/swig_python_wrap.c',
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
