from unittest import TestCase
from cryptopals import decrypt_single_byte_xor


class Test(TestCase):
    def test_decrypt_single_byte_xor(self):
        arg = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        res = decrypt_single_byte_xor(bytes.fromhex(arg))

        # In this case, the `score` function assigns the correct plaintext the smallest value, as expected,
        # but it's not at all clear it will do so in every case.
        self.assertEqual("Cooking MC's like a pound of bacon", res.decryption.get_plaintext())
