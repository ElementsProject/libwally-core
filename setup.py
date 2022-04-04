"""setuptools config for wallycore """
from setuptools import setup, Extension
import platform
import os,sys,copy,distutils.sysconfig, logging

CONFIGURE_ARGS = '--enable-swig-python --enable-python-manylinux --enable-ecmult-static-precomputation --enable-elements --disable-tests'

#logging.basicConfig(stream=sys.stderr, level=logging.INFO)
#log = logging.getLogger()
#log.info('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX {}'.format(os.environ))
#log.info('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX {}'.format(distutils.sysconfig.get_config_vars()))

distutils_env = distutils.sysconfig.get_config_vars()
configure_env = copy.deepcopy(os.environ)

if os.environ.get('GITHUB_ACTION') and os.environ.get('RUNNER_OS') == 'macOS' and \
    os.environ.get('RUNNER_ARCH') == 'X64' and os.environ.get('ARCHFLAGS','').endswith(' arm64'):
    # This is a github CI cross-compile for macOS M1
    #configure_env['CFLAGS'] = '-march arm64'
    #configure_env['LDFLAGS'] = '-march arm64'
    CONFIGURE_ARGS += ' --host x86_64-apple-darwin --target arm64-apple-macos'
    if 'PY_CFLAGS' in distutils_env:
        configure_env['CFLAGS'] = distutils_env['PY_CFLAGS']
        configure_env['LDFLAGS'] = distutils_env['PY_LDFLAGS']


is_windows = platform.system() == "Windows"

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
    # Borrowing config from wrap_js
    # TODO: Move this to another directory
    include_dirs = ['./src/wrap_js/windows_config'] + include_dirs

extra_compile_args = ['-flax-vector-conversions']

wally_ext = Extension(
    '_wallycore',
    define_macros=define_macros,
    include_dirs=include_dirs,
    extra_compile_args=extra_compile_args,
    sources=[
        'src/swig_python/swig_wrap.c' if is_windows else 'src/swig_python/swig_python_wrap.c',
        'src/wrap_js/src/combined.c',
        'src/wrap_js/src/combined_ccan.c',
        'src/wrap_js/src/combined_ccan2.c',
        ],
    )

kwargs = {
    'name': 'wallycore',
    'version': '0.8.4',
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

        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
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
