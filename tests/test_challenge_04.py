from unittest import TestCase
from cryptopals import find_single_byte_xor
import requests


class Test(TestCase):
    def test_find_single_byte_xor(self):
        expected = 170

        with requests.get('https://cryptopals.com/static/challenge-data/4.txt') as request:
            actual = find_single_byte_xor(request.text.splitlines())
            self.assertEqual(expected, actual)