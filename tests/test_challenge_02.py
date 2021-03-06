from unittest import TestCase
from cryptopals import fixed_xor


class Test(TestCase):
    def test_fixed_xor(self):
        expected = bytes.fromhex('746865206b696420646f6e277420706c6179')
        actual = fixed_xor(bytes.fromhex('1c0111001f010100061a024b53535009181c'),
                           bytes.fromhex('686974207468652062756c6c277320657965'))

        self.assertEqual(expected, actual)
