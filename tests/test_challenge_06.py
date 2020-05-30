from unittest import TestCase
from cryptopals import bitwise_hamming_distance, decrypt_repeating_key_xor
import base64
import requests

from . import lyrics


class Test(TestCase):
    def test_bitwise_hamming_distance(self):
        expected = 37
        actual = bitwise_hamming_distance(b"this is a test", b"wokka wokka!!!")

        self.assertEqual(expected, actual)

    def test_break_repeating_key(self):
        with requests.get('https://cryptopals.com/static/challenge-data/6.txt') as request:
            expected = lyrics
            actual = decrypt_repeating_key_xor(base64.b64decode(request.content))

            self.assertEqual(expected, actual)
