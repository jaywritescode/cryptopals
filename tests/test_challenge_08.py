from unittest import TestCase
from cryptopals import find_ecb_in_aes
import requests


class Test(TestCase):
    def test_find_ecb_in_aes(self):
        with requests.get('https://cryptopals.com/static/challenge-data/8.txt') as request:
            expected = 132
            actual = find_ecb_in_aes(request.text.splitlines())

            self.assertEqual(expected, actual)
