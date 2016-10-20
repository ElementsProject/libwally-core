"""setuptools config for wallycore """
from setuptools import setup

setup(
    name='wallycore',

    version='0.0.2',
    description='libwally Bitcoin library',
    long_description='Python bindings for the libwally Bitcoin library',
    url='https://github.com/jgriffiths/libwally-core',
    author='Jon Griffiths',
    author_email='jon_p_griffiths@yahoo.com',
    license='MIT',

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
    data_files=[('', ['src/.libs/libwallycore.so'])] ,
)
