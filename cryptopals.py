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

    Given numbers `m` and `n` as bytes, calculate the bitwise exclusive-or of `m` and `n`.

    :param m: a bytes
    :param n: another bytes
    :return: a bytes
    """
    if len(m) != len(n):
        raise ValueError("Expecting both arguments to have the same length.")

    return bytes(x ^ y for x, y in zip(m, n))


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


def try_decrypt_single_byte_xor(encrypted, keys):
    """
    Apply single-byte XOR decryption to `encrypted` for each of the given keys. Return only the printable Decryptions.

    :param encrypted: the message, a hex-encoded string
    :param keys: an iterable of keys to try
    :return: an iterable of printable Decryptions
    """
    decryptions = [Decryption.create(encrypted, key) for key in keys]

    # filter out plaintexts with non-printable characters
    return list(filter(lambda d: d.is_printable(), decryptions))


def decrypt_single_byte_xor(encrypted):
    """
    Set 1, challenge 3.

    You are given a hex-encoded string that has been single-byte xor'd against an ASCII character. Decrypt the string.

    Assume that all characters in the string are in string.printable.

    :param encrypted: the message, as bytes
    :return: the best Score when the string is decrypted against every ASCII character.
    """
    decryptions = try_decrypt_single_byte_xor(encrypted, range(1, 2 ** 8))
    if not decryptions:
        return nil_score

    return min(map(lambda p: Score(score(p), p), decryptions))


Score = namedtuple('Score', ['score', 'decryption'])

nil_score = Score(float('inf'), decryption=None)


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

  
def find_single_byte_xor(args):
  """
  Set 1, challenge 4.

  Given a collection of hex-encoded strings, determine which one was encrypted with single-byte xor.

  :param args: a list of hex-encoded strings
  :return: the index of the string encrypted with single-byte xor
  """
  result = min((decrypt_single_byte_xor(bytes.fromhex(line.strip())), idx) for idx, line in enumerate(args))
  return result[1]


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


def pairwise(iterable):
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)


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


def find_ecb_in_aes(args):
    """
    Set 1, challenge 8

    Given a collection of hex-encoded strings, determine which one was encrypted with ECB.

    :param args: a list of hex-encoded strings
    :return: the index of the string encrypted with ECB
    """
    for idx, line in enumerate(args):
        chunks = grouper(line, 16)

        seen = set()
        for chunk in chunks:
            if chunk in seen:
                return idx
            seen.add(chunk)


def encrypt_aes_with_ecb(plaintext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


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


def cbc_via_ecb(ciphertext, key, iv):
    """
    Set 2, challenge 10.

    :param ciphertext: base64-encoded ciphertext
    :param key: the key, in bytes
    :param iv: the initialization vector, in bytes
    :return: the plaintext, in bytes
    """
    plaintext = list()
    blocks = [iv] + [bytes(x) for x in grouper(ciphertext, len(key))]

    for previous, current in pairwise(blocks):
        plaintext.append(fixed_xor(attack_ecb_in_aes(current, key), previous))

    return b''.join(plaintext)



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
    pass