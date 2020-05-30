from unittest import TestCase
from cryptopals import pad_to_length


class Test(TestCase):
    def test_pad_to_length(self):
        expected = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        actual = pad_to_length(b"YELLOW SUBMARINE", 20)

        self.assertEqual(expected, actual)
