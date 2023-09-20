import unittest
from wallycore import init, cleanup, \
    ec_public_key_from_private_key, aes_cbc_with_ecdh_key, \
    AES_FLAG_ENCRYPT, AES_FLAG_DECRYPT


class AESTests(unittest.TestCase):

    def test_aes_cbc_ecdh(self):
        """Test python wrappers for aes_cbc_with_ecdh_key """
        # Alice generates an ephemeral keypair for her request.
        alice_priv = bytes.fromhex('1c6a837d1ac663fdc7f1002327ca38452766eaf4fe3b80ce620bf7cd3f584cf6')
        alice_pub = ec_public_key_from_private_key(alice_priv)
        # Bob generates an ephemeral keypair for his response.
        bob_priv = bytes.fromhex('0b6b3dc90d203d854100110788ac87d43aa00620c9cdb361b281b09022ef4b53')
        bob_pub = ec_public_key_from_private_key(bob_priv)
        # Bob also generates a secure random IV for encrypting the response.
        iv = bytes.fromhex('bd5d4724243880738e7e8b0c02658700')
        # Both parties must agree on a shared label to use.
        label = 'a sample label'.encode()
        # This is the example payload we are using.
        payload = 'This is an example response/payload to encrypt'.encode()

        # Test we handle messages up to and over AES_BLOCK_LEN boundaries
        for i in range(1, len(payload) + 1):
            # The protocol:
            # 1) Alice requests some data using her pubkey.
            # 2) Bob encrypts the response (payload) with his private key,
            #    a random IV, a shared label and Alice's pubkey.
            encrypted = aes_cbc_with_ecdh_key(bob_priv, iv, payload[0:i],
                                              alice_pub, label, AES_FLAG_ENCRYPT)
            # 3) Bob sends the encrypted data and his pubkey to Alice.
            # 4) Alice decrypts the payload with her private key and Bobs pubkey.
            decrypted = aes_cbc_with_ecdh_key(alice_priv, None, encrypted,
                                              bob_pub, label, AES_FLAG_DECRYPT)
            # Alice now has the unencrypted payload.
            self.assertEqual(decrypted.hex(), payload[0:i].hex())


if __name__ == '__main__':
    init(0)
    unittest.main()
    cleanup(0)
