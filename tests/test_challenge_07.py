from unittest import TestCase
from cryptopals import attack_ecb_in_aes
import requests
import base64

from . import lyrics


class Test(TestCase):
    def test_attack_ecb_in_aes(self):
        with requests.get('https://cryptopals.com/static/challenge-data/7.txt') as request:
            expected = lyrics
            actual = attack_ecb_in_aes(base64.b64decode(request.content), b'YELLOW SUBMARINE')

            # The decryption process adds padding to the ciphertext so that the ciphertext length is a multiple
            # of the key length. See challenge #9.
            self.assertTrue(actual.startswith(expected))
