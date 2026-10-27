"""Attacks on RSA: recover the private key by factoring the public modulus n."""
import math
import random
import time
from typing import Callable, Optional

from .rsa import ALPHABET, PrivateKey, PublicKey, decrypt, encrypt


class Timeout(Exception):
    """Raised when an attack exceeds its time budget."""


def _check_time(deadline: Optional[float]) -> None:
    if deadline is not None and time.perf_counter() > deadline:
        raise Timeout


# --- 1. Naive method: trial division --------------------------------------------------

def trial_division(n: int, deadline: Optional[float] = None) -> int:
    """Smallest prime factor of n, by testing every odd divisor up to sqrt(n).
    Cost: O(sqrt(n)) divisions, i.e. exponential in the number of bits of n."""
    if n % 2 == 0:
        return 2
    limit = math.isqrt(n)
    for start in range(3, limit + 1, 2_000_000):     # chunks of 1 million odd divisors
        for k in range(start, min(start + 2_000_000, limit + 1), 2):
            if n % k == 0:
                return k
        _check_time(deadline)
    return n


# --- 2. Pollard's rho algorithm ----------------------------------------------------------

def pollard_rho(n: int, deadline: Optional[float] = None, rng: random.Random = random) -> int:
    """A non-trivial factor of the composite number n.

    The sequence x_{i+1} = f(x_i) = x_i^2 + c (mod n) eventually cycles modulo the
    unknown prime factor p (it lives in the finite set Z/pZ), which draws the
    letter rho. Floyd's "tortoise and hare" detects the cycle: x moves one step,
    y two steps, and gcd(|x - y|, n) reveals p as soon as x = y (mod p).
    Expected cost: O(n^(1/4)) iterations.

    If the gcd jumps directly to n (both cycles found at once), we restart with
    another constant c and starting point instead of giving up.
    """
    if n % 2 == 0:
        return 2
    c, x0 = 1, 2                         # f(x) = x^2 + 1, x0 = 2, as in the original project
    while True:
        x = y = x0
        d = 1
        steps = 0
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            steps += 1
            if steps % 10_000 == 0:
                _check_time(deadline)
        if d != n:
            return d
        c, x0 = rng.randrange(1, n - 1), rng.randrange(2, n - 1)


# --- Full attack: from the public key to the private key ------------------------------

def recover_private_key(public: PublicKey, factor: Callable[..., int] = pollard_rho,
                        time_limit: Optional[float] = None) -> PrivateKey:
    """Factor n, then rebuild phi(n) and d exactly like the key owner would."""
    deadline = None if time_limit is None else time.perf_counter() + time_limit
    p = factor(public.n, deadline=deadline)
    q = public.n // p
    d = pow(public.e, -1, (p - 1) * (q - 1))
    return PrivateKey(public.n, d, p, q)


def break_rsa(cipher: list[int], public: PublicKey, factor: Callable[..., int] = pollard_rho,
              time_limit: Optional[float] = None) -> str:
    """Decrypt a message using only the public key."""
    return decrypt(cipher, recover_private_key(public, factor, time_limit))


# --- Bonus: why real RSA never encrypts letter by letter --------------------------------

def codebook_attack(cipher: list[int], public: PublicKey) -> str:
    """Letter-by-letter RSA is deterministic: each letter always gives the same number.
    Encrypting the 26 letters with the public key is enough to read any message,
    whatever the key size. Real RSA prevents this with random padding (OAEP)."""
    codebook = {y: letter for letter, y in zip(ALPHABET, encrypt(ALPHABET, public))}
    return "".join(codebook[y] for y in cipher)
