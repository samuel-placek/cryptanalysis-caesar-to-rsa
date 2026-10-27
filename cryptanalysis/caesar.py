"""Caesar cipher on the 26-letter alphabet a-z, and two attacks against it."""
from collections import Counter

from .words import is_word

ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def shift_letter(c: str, k: int) -> str:
    return ALPHABET[(ALPHABET.index(c) + k) % 26]


def encrypt(text: str, k: int) -> str:
    """Shift every letter of `text` by k positions (k can be any integer)."""
    return "".join(shift_letter(c, k) for c in text)


def decrypt(cipher: str, k: int) -> str:
    return encrypt(cipher, -k)


# --- Attack 1: frequency analysis ------------------------------------------------

def guess_shift(cipher: str, reference: str = "e") -> int:
    """Assume the most frequent letter of the cipher encrypts `reference`
    ('e', the most frequent letter in French). Ties are broken alphabetically."""
    counts = Counter(cipher)
    most_common = min(counts, key=lambda c: (-counts[c], c))
    return (ALPHABET.index(most_common) - ALPHABET.index(reference)) % 26


def frequency_attack(cipher: str) -> str:
    return decrypt(cipher, guess_shift(cipher))


# --- Attack 2: brute force + dictionary ---------------------------------------------

def brute_force_attack(cipher: str) -> list[str]:
    """Try the 26 shifts and keep the candidates that are French words.
    Returns every valid candidate: more than one means the result is ambiguous."""
    candidates = (decrypt(cipher, k) for k in range(26))
    return [c for c in candidates if is_word(c)]
