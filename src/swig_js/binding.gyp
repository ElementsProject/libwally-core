{
  "targets": [
    {
      "target_name": "copy_srcs",
      "copies": [
        {
          "files": [ "<(libwally_dir)/src/internal.h", "<(libwally_dir)/src/ccan/ccan/crypto/sha512/sha512.c", "<(libwally_dir)/src/ccan/ccan/crypto/ripemd160/ripemd160.c", "<(libwally_dir)/src/ccan/ccan/crypto/sha256/sha256.c", "<(libwally_dir)/src/secp256k1/src/secp256k1.c",  "<(libwally_dir)/src/secp256k1/src/util.h", "<(libwally_dir)/src/internal.c", "<(libwally_dir)/src/base58.c", "<(libwally_dir)/src/aes.c", "<(libwally_dir)/src/scrypt.c", "<(libwally_dir)/src/pbkdf2.c", "<(libwally_dir)/src/hmac.c", "<(libwally_dir)/src/bip38.c", "<(libwally_dir)/src/sign.c", "<(libwally_dir)/src/bip32.c", "<(libwally_dir)/src/elements.c" ],
          "destination": "src"
        }
      ],
      "conditions": [
        [ 'OS=="win"', {
          "copies+=": [
            {
              "files": [ "windows_config/config.h", "windows_config/libsecp256k1-config.h" ],
              "destination": "src"
            }
          ]
        }],
      ]
    },
    {
      "target_name": "deps",
      "dependencies": [ "copy_srcs" ],
      "sources": [ "src/aes.c", "src/base58.c", "src/bip38.c", "src/hmac.c", "src/internal.c", "src/pbkdf2.c", "src/ripemd160.c", "src/scrypt.c", "src/secp256k1.c", "src/sha256.c", "src/sha512.c", "src/sign.c", "src/bip32.c", "src/elements.c" ],
      "defines": [ "SWIG_JAVASCRIPT_BUILD", "HAVE_CONFIG_H" ],
      "include_dirs": [ "src", "<(libwally_dir)", "<(libwally_dir)/src", "<(libwally_dir)/src/secp256k1", "<(libwally_dir)/src/secp256k1/src", "<(libwally_dir)/src/ccan" ],
      "type": "static_library"
    },
    {
      "target_name": "wallycore",
      "dependencies": [ "deps" ],
      "sources": [ "nan_wrap.cc" ],
      "include_dirs": [ "<(libwally_dir)/src", "<!(node -e \"require('nan')\")" ],
      "defines": [ "SWIG_JAVASCRIPT_BUILD", "HAVE_CONFIG_H" ],
      "conditions": [
        [ 'OS=="win"', {
          "libraries": [ "Release/deps.lib" ],
        }],
        [ 'OS!="win"', {
          "libraries": [ "Release/deps.a" ],
        }]
      ]
    }
  ],
  "conditions": [
    [ 'OS=="mac"', {
      "xcode_settings": {
        "CLANG_CXX_LIBRARY": "libc++"
      }
    }],
    [ 'OS=="win"', {
      "variables": {
        "libwally_dir": "<!(echo %LIBWALLY_DIR%)"
      }
    }],
    [ 'OS!="win"', {
      "variables": {
        "libwally_dir": "<!(echo $LIBWALLY_DIR)"
      }
    }]
  ]
}
