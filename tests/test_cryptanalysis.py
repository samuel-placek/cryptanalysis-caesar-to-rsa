import random

import pytest

from cryptanalysis import attacks, caesar, rsa, words


# --- Word list ----------------------------------------------------------------------

def test_word_list():
    assert words.is_word("envie") and not words.is_word("gpxkg")
    w = words.random_word(7, random.Random(0))
    assert len(w) == 7 and words.is_word(w)
    assert len(words.random_text(200, random.Random(0))) == 200


# --- Caesar --------------------------------------------------------------------------

@pytest.mark.parametrize("k", range(-30, 30))
def test_caesar_round_trip(k):
    assert caesar.decrypt(caesar.encrypt("bonjourzz", k), k) == "bonjourzz"


def test_caesar_example_from_slides():
    assert caesar.encrypt("envie", 2) == "gpxkg"
    assert caesar.frequency_attack("gpxkg") == "envie"


@pytest.mark.parametrize("k", range(26))
def test_frequency_attack_any_shift(k):
    # 'e' is the most frequent letter of this word, so the attack must work for every shift
    # (the original version failed whenever 'e' was encrypted as a, b, c or d)
    assert caesar.frequency_attack(caesar.encrypt("envie", k)) == "envie"


def test_brute_force_attack():
    assert "envie" in caesar.brute_force_attack(caesar.encrypt("envie", 11))


# --- RSA -----------------------------------------------------------------------------

def test_example_from_slides():
    # p = 3, q = 11, e = 3, d = 7: 'f' (rank 5) -> 5^3 = 125 = 26 mod 33 -> 26^7 = 5 mod 33
    key_pub, key_priv = rsa.PublicKey(33, 3), rsa.PrivateKey(33, 7, 3, 11)
    assert rsa.encrypt("f", key_pub) == [26]
    assert rsa.decrypt([26], key_priv) == "f"


@pytest.mark.parametrize("n_bits", [10, 16, 32, 64, 128, 512])
def test_rsa_round_trip(n_bits):
    public, private = rsa.generate_keys(n_bits, random.Random(n_bits))
    assert public.n.bit_length() == n_bits
    message = "lachiffrementrsa"
    assert rsa.decrypt(rsa.encrypt(message, public), private) == message


def test_primality():
    primes = {p for p in range(2, 500) if all(p % k for k in range(2, p))}
    assert {m for m in range(500) if rsa.is_probable_prime(m)} == primes


# --- Attacks on RSA ------------------------------------------------------------------

@pytest.mark.parametrize("factor", [attacks.trial_division, attacks.pollard_rho])
@pytest.mark.parametrize("n_bits", [12, 24, 40])
def test_factorisation(factor, n_bits):
    _, private = rsa.generate_keys(n_bits, random.Random(n_bits))
    assert factor(private.n) in (private.p, private.q)


@pytest.mark.parametrize("n_bits", [20, 40, 60])
def test_break_rsa_with_pollard(n_bits):
    public, _ = rsa.generate_keys(n_bits, random.Random(n_bits))
    cipher = rsa.encrypt("messagesecret", public)
    assert attacks.break_rsa(cipher, public) == "messagesecret"


def test_timeout():
    public, _ = rsa.generate_keys(120, random.Random(1))
    with pytest.raises(attacks.Timeout):
        attacks.recover_private_key(public, attacks.pollard_rho, time_limit=0.05)


def test_codebook_attack_ignores_key_size():
    public, _ = rsa.generate_keys(2048, random.Random(3))
    cipher = rsa.encrypt("messagesecret", public)
    assert attacks.codebook_attack(cipher, public) == "messagesecret"
