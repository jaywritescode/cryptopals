import base64
from collections import Counter, namedtuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import heapq
from functools import singledispatch
import itertools
import string

letter_frequencies = {
    'a': 0.0834,
    'b': 0.0154,
    'c': 0.0273,
    'd': 0.0414,
    'e': 0.126,
    'f': 0.0203,
    'g': 0.0192,
    'h': 0.0611,
    'i': 0.0671,
    'j': 0.0023,
    'k': 0.0086,
    'l': 0.0424,
    'm': 0.0253,
    'n': 0.068,
    'o': 0.077,
    'p': 0.0166,
    'q': 0.0009,
    'r': 0.0568,
    's': 0.0611,
    't': 0.0937,
    'u': 0.0285,
    'v': 0.0106,
    'w': 0.0234,
    'x': 0.002,
    'y': 0.0204,
    'z': 0.0006
}


def to_base64(hexstring):
    """
    Set 1, challenge 1.

    You are given a number `h` as a hexadecimal-encoded string. That is to say, given a (ASCII-compatible) plaintext
    string, `h` is the concatenation of mapping each character to its base-16 ASCII value. Find the base64-encoding of
    that plaintext string.

    >>> to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    :param hexstring: a hexadecimal-encoded string
    :return: the base64 encoding of `hexstring` as a `bytes`
    """
    return base64.b64encode(bytes.fromhex(hexstring))


def fixed_xor(m, n):
    """
    Set 1, challenge 2.

    Given numbers `m` and `n` as hex-encoded strings, calculate the bitwise exclusive-or of `m` and `n`.

    >>> fixed_xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')
    '746865206b696420646f6e277420706c6179'

    :param m: a hex-encoded string
    :param n: a hex-encoded string
    :return: a hex-encoded string
    """
    if len(m) != len(n):
        raise ValueError("Expecting both arguments to have the same length.")

    return bytes(x ^ y for x, y in zip(bytes.fromhex(m), bytes.fromhex(n))).hex()


@singledispatch
def single_byte_xor(encrypted, key):
    """
    Decrypt a message encoded with a single-byte key.

    >>> single_byte_xor(b'\x1b77316?x\x15\x1b\x7f+x413=x9x(7-6<x7>x:9;76', ord('X'))
    b"Cooking MC's like a pound of bacon"

    :param encrypted: the message, as an iterable of bytes
    :param key: the key, 0 <= key < 2 ** 8
    :return: the plaintext bytes
    """
    return bytes(c ^ key for c in encrypted)


@single_byte_xor.register(str)
def _(encrypted, key):
    """
    Decrypt a message encoded with a single-byte key.

    >>> single_byte_xor('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', ord('X'))
    b"Cooking MC's like a pound of bacon"

    :param encrypted: the message, a hex-encoded string
    :param key: the key, 0 <= key < 2 ** 8
    :return: the plaintext bytes
    """
    return bytes(c ^ key for c in bytes.fromhex(encrypted))


class Decryption:
    def __init__(self, plaintext, key):
        self.plaintext = [chr(c) for c in plaintext]
        self.key = key

    def is_printable(self):
        return all(c in string.printable for c in self.plaintext)

    def get_plaintext(self):
        return ''.join(self.plaintext)

    def __iter__(self):
        return iter(self.plaintext)

    def __repr__(self):
        return "Decryption(plaintext={!r}, key={})".format(''.join(self.plaintext), self.key)

    @staticmethod
    def create(ciphertext, key):
        return Decryption(single_byte_xor(ciphertext, key), key)


Score = namedtuple('Score', ['score', 'decryption'])

nil_score = Score(float('inf'), decryption=None)


def decrypt_single_byte_xor_in_range(encrypted, keys):
    """
    Apply single-byte XOR decryption to `encrypted` for each of the given keys. Return only the printable Decryptions.

    :param encrypted: the message, a hex-encoded string
    :param keys: an iterable of keys to try
    :return: an iterable of printable Decryptions
    """
    decryptions = [Decryption.create(encrypted, key) for key in keys]

    # filter out plaintexts with non-printable characters
    decryptions = list(filter(lambda d: d.is_printable(), decryptions))

    return decryptions


def decrypt_single_byte_xor(encrypted):
    """
    Set 1, challenge 3.

    You are given a hex-encoded string that has been single-byte xor'd against an ASCII character. Decrypt the string.

    Assume that all characters in the string are in string.printable.

    :param encrypted: the message, a hex-encoded string
    :return: the best Score when the string is decrypted against every ASCII character.
    """
    decryptions = decrypt_single_byte_xor_in_range(encrypted, range(1, 2 ** 8))
    if not decryptions:
        return nil_score

    return min(map(lambda p: Score(score(p), p), decryptions))


def score(text):
    """
    "Scores" the likelihood that a piece of text is in English.

    :param text: the text in question, as a str
    :return: a value indicating how close `text` is to expected English text, in terms of letter frequency.
        The lower the value, the more likely the text is English.
    """
    # ignore non-letter characters
    counter = Counter(c.lower() for c in text if c.isalpha())
    letter_count = sum(counter.values())

    if not letter_count:
        return float('inf')

    total_variance = 0.0
    for letter, frequency in letter_frequencies.items():
        total_variance += abs(counter[letter] / letter_count - frequency)

    return total_variance

@singledispatch
def repeating_key_xor(text, key):
    """
    Set 1, challenge 5.

    Encrypt plaintext with a repeating, multi-byte key.

    For every byte in the plaintext, byte i is xor'd with key[i % len(key)] and each result is converted to a
    two-character hexadecimal number possibly including a leading zero. We return the concatenation of those results.

    >>> repeating_key_xor("Burning 'em, if you ain't quick and nimble\\nI go crazy when I hear a cymbal", "ICE")
    '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

    :param text: the text, either plaintext or ciphertext, as bytes
    :param key: the key, as a str
    :return: a hex-encoded string
    """
    encrypted = [p ^ k for p, k in zip(text, itertools.cycle([ord(c) for c in key]))]
    return bytes(encrypted).hex()


@repeating_key_xor.register(str)
def _(text, key):
    """
    Set 1, challenge 5.

    Encrypt plaintext with a repeating, multi-byte key.

    For every byte in the plaintext, byte i is xor'd with key[i % len(key)] and each result is converted to a
    two-character hexadecimal number possibly including a leading zero. We return the concatenation of those results.

    >>> repeating_key_xor(b"Burning 'em, if you ain't quick and nimble\\nI go crazy when I hear a cymbal", "ICE")
    '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

    :param text: the text, either plaintext or ciphertext, as a str
    :param key: the key, as a str
    :return: a hex-encoded string
    """
    encrypted = [p ^ k for p, k in zip((ord(c) for c in text), itertools.cycle([ord(c) for c in key]))]
    return bytes(encrypted).hex()


def bitwise_hamming_distance(m, n):
    """
    Find the bitwise Hamming distance between two str objects.

    Given two iterables m, n of equal length k, the Hamming distance is the number of indices i < k such that m[i] != n[i].

    In this case, we're finding the Hamming distance between two bitstrings m and n, which is the same as the number of ones in m ^ n.

    >>> bitwise_hamming_distance(b"this is a test", b"wokka wokka!!!")
    37

    :param m: a bytes object
    :param n: another bytes object
    :return: the bitwise Hamming distance between `m` and `n`
    """
    if len(m) != len(n):
        raise ValueError("m and n should be the same length in bytes")

    def count_ones(b):
        count = 0
        while b > 0:
            b = b & (b - 1)
            count += 1
        return count

    return sum(count_ones(i) for i in (x ^ y for x, y in zip(m, n)))


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)


KeySize = namedtuple('KeySize', ['normalized_hamming_distance', 'key_size'])


def break_repeating_key_xor(encrypted):
    def hamming_distance(keysize):
        return bitwise_hamming_distance(encrypted[:keysize], encrypted[keysize:2 * keysize])

    heap = [KeySize(hamming_distance(n) / n, n) for n in range(2, 40)]
    heapq.heapify(heap)

    def fail_fast_decrypt(columns):
        res = []
        for column in columns:
            dec = decrypt_single_byte_xor(column)
            if dec is nil_score:
                return None
            res.append(dec)
        return res

    while True:
        if not heap:
            raise ValueError("No key length worked!")

        chunks = list(grouper(encrypted, heapq.heappop(heap).key_size, fillvalue=0))
        columns = list(itertools.zip_longest(*chunks))

        individual_keys = fail_fast_decrypt(columns)
        if individual_keys:
            yield ''.join([chr(score.decryption.key) for score in individual_keys])


def decrypt_repeating_key_xor(encrypted):
    """
    Set 1, challenge 6.

    :param encrypted:
    :return:
    """
    while True:
        keys = break_repeating_key_xor(encrypted)
        return bytes.fromhex(repeating_key_xor(encrypted, next(keys)))


def attack_ecb_in_aes(encrypted, key):
    """
    Set 1, challenge 7

    :param encrypted:
    :return:
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB(), default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted) + decryptor.finalize()


def pad_to_length(block, length):
    """
    Set 2, challenge 9

    Pad a block of text to the given length for PKCS#7.

    >>> pad_to_length(b"YELLOW SUBMARINE", 20)
    b"YELLOW SUBMARINE\x04\x04\x04\x04"

    :param block: the block to pad, as a bytes
    :param length: the total length of the padded block
    :return: the padded block, as a bytes
    """
    block_len = len(block)
    padding_amt = length - block_len

    return block + bytes([padding_amt] * padding_amt)



#
#
#
#
# def index_of_coincidence(text):
#     """
#     The index of coincidence for a given text is the likelihood of choosing two characters at random from the text
#     (without replacement) and having those two characters be the same.
#
#     For English text, the expected index of coincidence ≈ 1.73. That value is normalized across all 26 letters.
#     The formula below gives the non-normalized value, called kappa-plaintext.
#
#     In English, kappa-plaintext = IC / (1/26) ≈ 0.067
#
#     :param text:
#     :return:
#     """
#     counter = Counter(filter(lambda c: c in string.ascii_lowercase, text.lower()))
#     length = sum(counter.values())
#
#     return sum(max(0, counter[i] * counter[i] - 1) for i in letter_frequencies) / (length * (length - 1))
#


if __name__ == '__main__':
    import unittest

    class TestChallenge1(unittest.TestCase):
        def test_to_base(self):
            expected = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
            actual = to_base64('49276d206b696c6c696e6720796f757220627261696e206c'
                         '696b65206120706f69736f6e6f7573206d757368726f6f6d')

            self.assertEqual(expected, actual)

    class TestChallenge2(unittest.TestCase):
        def test_fixed_xor(self):
            expected = '746865206b696420646f6e277420706c6179'
            actual = fixed_xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')

            self.assertEqual(expected, actual)

    class TestChallenge3(unittest.TestCase):
        def test_decrypt_single_byte_xor(self):
            arg = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
            res = decrypt_single_byte_xor(arg)

            # In this case, the `score` function assigns the correct plaintext the smallest value, as expected,
            # but it's not at all clear it will do so in every case.
            self.assertEqual("Cooking MC's like a pound of bacon", res.decryption.get_plaintext())

    import requests

    def make_url(id):
        return 'https://cryptopals.com/static/challenge-data/{}.txt'.format(id)

    class TestChallenge4(unittest.TestCase):
        def test_find_encrypted_with_single_byte_xor(self):
            expected = 170

            with requests.get(make_url('4')) as request:
                res = min((decrypt_single_byte_xor(line.strip()), idx)
                          for idx, line in enumerate(request.text.splitlines()))
                self.assertEqual(expected, res[1])

    class TestChallenge5(unittest.TestCase):
        def test_repeating_key_xor(self):
            expected = ('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527'
                        '2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')
            actual = repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")

            self.assertEqual(expected, actual)

    lyrics = (b"I'm back and I'm ringin' the bell \n"
                            b"A rockin' on the mike while the fly girls yell \n"
                            b"In ecstasy in the back of me \n"
                            b"Well that's my DJ Deshay cuttin' all them Z's \n"
                            b"Hittin' hard and the girlies goin' crazy \n"
                            b"Vanilla's on the mike, man I'm not lazy. \n\n"
                            b"I'm lettin' my drug kick in \n"
                            b"It controls my mouth and I begin \n"
                            b"To just let it flow, let my concepts go \n"
                            b"My posse's to the side yellin', Go Vanilla Go! \n\n"
                            b"Smooth 'cause that's the way I will be \n"
                            b"And if you don't give a damn, then \n"
                            b"Why you starin' at me \n"
                            b"So get off 'cause I control the stage \n"
                            b"There's no dissin' allowed \n"
                            b"I'm in my own phase \n"
                            b"The girlies sa y they love me and that is ok \n"
                            b"And I can dance better than any kid n' play \n\n"
                            b"Stage 2 -- Yea the one ya' wanna listen to \n"
                            b"It's off my head so let the beat play through \n"
                            b"So I can funk it up and make it sound good \n"
                            b"1-2-3 Yo -- Knock on some wood \n"
                            b"For good luck, I like my rhymes atrocious \n"
                            b"Supercalafragilisticexpialidocious \n"
                            b"I'm an effect and that you can bet \n"
                            b"I can take a fly girl and make her wet. \n\n"
                            b"I'm like Samson -- Samson to Delilah \n"
                            b"There's no denyin', You can try to hang \n"
                            b"But you'll keep tryin' to get my style \n"
                            b"Over and over, practice makes perfect \n"
                            b"But not if you're a loafer. \n\n"
                            b"You'll get nowhere, no place, no time, no girls \n"
                            b"Soon -- Oh my God, homebody, you probably eat \n"
                            b"Spaghetti with a spoon! Come on and say it! \n\n"
                            b"VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \n"
                            b"Intoxicating so you stagger like a wino \n"
                            b"So punks stop trying and girl stop cryin' \n"
                            b"Vanilla Ice is sellin' and you people are buyin' \n"
                            b"'Cause why the freaks are jockin' like Crazy Glue \n"
                            b"Movin' and groovin' trying to sing along \n"
                            b"All through the ghetto groovin' this here song \n"
                            b"Now you're amazed by the VIP posse. \n\n"
                            b"Steppin' so hard like a German Nazi \n"
                            b"Startled by the bases hittin' ground \n"
                            b"There's no trippin' on mine, I'm just gettin' down \n"
                            b"Sparkamatic, I'm hangin' tight like a fanatic \n"
                            b"You trapped me once and I thought that \n"
                            b"You might have it \n"
                            b"So step down and lend me your ear \n"
                            b"'89 in my time! You, '90 is my year. \n\n"
                            b"You're weakenin' fast, YO! and I can tell it \n"
                            b"Your body's gettin' hot, so, so I can smell it \n"
                            b"So don't be mad and don't be sad \n"
                            b"'Cause the lyrics belong to ICE, You can call me Dad \n"
                            b"You're pitchin' a fit, so step back and endure \n"
                            b"Let the witch doctor, Ice, do the dance to cure \n"
                            b"So come up close and don't be square \n"
                            b"You wanna battle me -- Anytime, anywhere \n\n"
                            b"You thought that I was weak, Boy, you're dead wrong \n"
                            b"So come on, everybody and sing this song \n\n"
                            b"Say -- Play that funky music Say, go white boy, go white boy go \n"
                            b"play that funky music Go white boy, go white boy, go \n"
                            b"Lay down and boogie and play that funky music till you die. \n\n"
                            b"Play that funky music Come on, Come on, let me hear \n"
                            b"Play that funky music white boy you say it, say it \n"
                            b"Play that funky music A little louder now \n"
                            b"Play that funky music, white boy Come on, Come on, Come on \n"
                            b"Play that funky music \n")

    class TestChallenge6(unittest.TestCase):
        def test_bitwise_hamming_distance(self):
            expected = 37
            actual = bitwise_hamming_distance(b"this is a test", b"wokka wokka!!!")

            self.assertEqual(expected, actual)

        def test_break_repeating_key(self):
            with requests.get(make_url('6')) as request:
                expected = lyrics
                actual = decrypt_repeating_key_xor(base64.b64decode(request.content))

                self.assertEqual(expected, actual)

    class TestChallenge7(unittest.TestCase):
        def test_attack_ecb_in_aes(self):
            with requests.get(make_url('7')) as request:
                expected = lyrics
                actual = attack_ecb_in_aes(base64.b64decode(request.content), b'YELLOW SUBMARINE')

                # The decryption process adds padding to the ciphertext so that the ciphertext length is a multiple
                # of the key length. See challenge #9.
                self.assertTrue(actual.startswith(expected))

    class TestChallenge8(unittest.TestCase):
        """
        This challenge just uses existing code from the previous challenges.
        """
        def solve(self):
            """
            For each line, we look for a substring that appears more than once. This shouldn't happen in strong encryption,
            but it can happen with ECB-style encryption ("electronic code book").

            :return: the line number in the request that's encrypted with ECB
            """
            with requests.get(make_url('8')) as request:
                for idx, line in enumerate(request.content.splitlines()):
                    chunks = grouper(line, 16)

                    seen = set()
                    for chunk in chunks:
                        if chunk in seen:
                            return idx

                        seen.add(chunk)

        def test_find_aes_in_ecb_mode(self):
            expected = 132
            actual = self.solve()

            self.assertEqual(expected, actual)

    class TestChallenge9(unittest.TestCase):
        def test_pad_to_length(self):
            expected = b"YELLOW SUBMARINE\x04\x04\x04\x04"
            actual = pad_to_length(b"YELLOW SUBMARINE", 20)

            self.assertEqual(expected, actual)

    unittest.main()