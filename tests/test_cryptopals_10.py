from unittest import TestCase
from cryptopals import cbc_via_ecb
import requests
import base64

from . import lyrics


class Test(TestCase):
    def test_cbc_via_ecb(self):
        with requests.get('https://cryptopals.com/static/challenge-data/10.txt') as request:
            expected = lyrics
            actual = cbc_via_ecb(base64.b64decode(request.content), b'YELLOW SUBMARINE', b'\x00' * 16)

            # the actual result includes some addition trailing padding that we don't care about
            self.assertTrue(actual.startswith(expected))
