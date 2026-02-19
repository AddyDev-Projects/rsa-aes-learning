import unittest

from src.encryption import RSA_KeyPair, encrypt_message, decrypt_message, encrypt_large_data, decrypt_large_data


class TestEncryption(unittest.TestCase):

    def setUp(self):

        self.keypair = RSA_KeyPair()

    def test_small_message(self):

        msg = "Test message"

        cipher = encrypt_message(msg, self.keypair.public_key)

        decrypted = decrypt_message(cipher, self.keypair.private_key).decode("utf-8")

        self.assertEqual(msg, decrypted)

    def test_large_message(self):

        msg = "A" * 500

        cipher = encrypt_large_data(msg, self.keypair.public_key)

        decrypted = decrypt_large_data(cipher, self.keypair.private_key).decode("utf-8")

        self.assertEqual(msg, decrypted)


if __name__ == "__main__":

    unittest.main()
