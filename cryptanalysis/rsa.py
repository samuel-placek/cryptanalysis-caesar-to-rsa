"""Textbook RSA, applied letter by letter as in the original project.

Each letter is mapped to its rank x in the alphabet ('a' = 0, ..., 'z' = 25) and
encrypted as y = x^e mod n. Decryption computes x = y^d mod n, where
d is the inverse of e modulo phi(n) = (p - 1)(q - 1).
"""
import math
import random
from dataclasses import dataclass

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int


@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int
    p: int
    q: int


def is_probable_prime(m: int, rounds: int = 25, rng: random.Random = random) -> bool:
    """Miller-Rabin primality test (error probability < 4^-rounds)."""
    if m < 2:
        return False
    for p in SMALL_PRIMES:
        if m % p == 0:
            return m == p
    s, t = 0, m - 1
    while t % 2 == 0:
        s, t = s + 1, t // 2
    for _ in range(rounds):
        a = rng.randrange(2, m - 1)
        x = pow(a, t, m)
        if x in (1, m - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, m)
            if x == m - 1:
                break
        else:
            return False
    return True


def random_prime(bits: int, rng: random.Random = random) -> int:
    """A random prime with exactly `bits` bits, whose two top bits are set
    (so that the product of two such primes has exactly 2 * bits bits)."""
    while True:
        candidate = rng.getrandbits(bits) | (0b11 << (bits - 2)) | 1
        if is_probable_prime(candidate, rng=rng):
            return candidate


def generate_keys(n_bits: int, rng: random.Random = random) -> tuple[PublicKey, PrivateKey]:
    """RSA key pair whose modulus n = p * q has exactly n_bits bits (p and q
    have n_bits / 2 bits each). e = 65537 when possible, as in real-world RSA."""
    if n_bits < 10 or n_bits % 2:
        raise ValueError("n_bits must be an even number >= 10")
    while True:
        p = random_prime(n_bits // 2, rng)
        q = random_prime(n_bits // 2, rng)
        if p == q:
            continue
        n, phi = p * q, (p - 1) * (q - 1)
        for e in (65537, 257, 17, 5, 3):
            if e < phi and math.gcd(e, phi) == 1:
                return PublicKey(n, e), PrivateKey(n, pow(e, -1, phi), p, q)


def encrypt(text: str, key: PublicKey) -> list[int]:
    return [pow(ALPHABET.index(c), key.e, key.n) for c in text]


def decrypt(cipher: list[int], key: PrivateKey) -> str:
    return "".join(ALPHABET[pow(y, key.d, key.n)] for y in cipher)
