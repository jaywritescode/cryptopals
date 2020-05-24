import base64
from collections import Counter, namedtuple
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

    @staticmethod
    def create(ciphertext, key):
        return Decryption(single_byte_xor(ciphertext, key), key)


Score = namedtuple('Score', ['score', 'decryption'])

nil_score = Score(float('inf'), decryption=None)


def decrypt_single_byte_xor(encrypted):
    """
    Set 1, challenge 3.

    You are given a hex-encoded string that has been single-byte xor'd against an ASCII character. Decrypt the string.

    Assume that all characters in the string are in string.printable.

    :param encrypted: the message, a hex-encoded string
    :return: the best Score when the string is decrypted against every ASCII character.
    """
    decryptions = [Decryption.create(encrypted, key) for key in range(1, 2 ** 8)]

    # filter out plaintexts with non-printable characters
    decryptions = list(filter(lambda d: d.is_printable(), decryptions))

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


def repeating_key_xor(plaintext, key):
    """
    Set 1, challenge 5.

    Encrypt plaintext with a repeating, multi-byte key.

    For every byte in the plaintext, byte i is xor'd with key[i % len(key)] and each result is converted to a
    two-character hexadecimal number possibly including a leading zero. We return the concatenation of those results.

    >>> repeating_key_xor("Burning 'em, if you ain't quick and nimble\\nI go crazy when I hear a cymbal", "ICE")
    '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

    :param plaintext: the plaintext, as a str
    :param key: the key, as a str
    :return: a hex-encoded string
    """
    encrypted = [p ^ k for p, k in zip((ord(c) for c in plaintext), itertools.cycle([ord(c) for c in key]))]
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
    print("attempting break repeating key xor")

    def guess_keysize(keysize):
        return bitwise_hamming_distance(encrypted[:keysize], encrypted[keysize:2 * keysize])

    heap = [KeySize(guess_keysize(n) / n, n) for n in range(2, 40)]
    heapq.heapify(heap)

    while True:
        if not heap:
            raise ValueError("No key length worked!")

        keysize_guess = heapq.heappop(heap).key_size

        chunks = list(grouper(encrypted, keysize_guess, fillvalue=0))
        cols = list(itertools.zip_longest(*chunks))

        colkeys = [decrypt_single_byte_xor(col) for col in cols]

        print(colkeys)

        if not any(x is nil_score for x in colkeys):
            return ''.join([chr(score.decryption.key) for score in colkeys])







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
    # tests for parts 1, 2, 5 and part of 6
    import doctest
    doctest.testmod()

    # test for part 3 (which is potentially flaky
    x = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    print(decrypt_single_byte_xor(x))

    import requests

    def make_url(id):
        return 'https://cryptopals.com/static/challenge-data/{}.txt'.format(id)

    # test for part 4
    with requests.get(make_url('4')) as request:
        m = min((decrypt_single_byte_xor(line.strip()), idx) for idx, line in enumerate(request.text.splitlines()))
        print(tuple((m[0].decryption, m[1])))

    with requests.get(make_url('6')) as request:
        unencoded = base64.b64decode(request.content)
        print(break_repeating_key_xor(unencoded))
        print("done")
