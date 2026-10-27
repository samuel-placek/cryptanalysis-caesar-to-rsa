# Cryptanalysis: from the Caesar cipher to RSA

> 🇫🇷 [Version française](README.fr.md)

**How hard is it to read an encrypted message without the key?** Implementation of two ciphers, the Caesar cipher and RSA, and experimental attacks against them: frequency analysis and brute force for Caesar, factoring the public key with trial division and Pollard's rho algorithm for RSA.

*TIPE (research project of the French preparatory classes, MP, computer science option) · 2024–2025 · Samuel Placek · Theme: "Transition, transformation, conversion"*

![Time needed to factor an RSA modulus](figures/rsa_factoring_time.png)

## Key results

**Caesar cipher**
- **Frequency analysis** ("the most frequent letter stands for *e*") is unreliable on single words: **6% to 25% success** depending on their length. It needs real text: **88% success on 100 letters, 99% on 300**.
- **Brute force** over the 26 shifts, with an automatic dictionary check, always finds the original word among the candidates. The answer is unique for **more than 99% of words of 5 letters or more**; very short words stay ambiguous (96% of 2-letter words have several valid decryptions).

**RSA**
- **Trial division** (the naive method) needs about √n operations: its time is multiplied by about 4 every 4 bits of the modulus n, and it already takes 6.6 seconds for a 56-bit n.
- **Pollard's rho** needs about n^¼ operations, so it grows twice as slowly: it factors a **96-bit modulus in about 26 seconds**. With a 1-second budget per key, it decrypts **100% of messages up to 72 bits**, and none at all from 88 bits.
- Extrapolated to a real **2,048-bit key** (time doubling every 4 bits from the 26 seconds measured at 96 bits), Pollard's rho would need about **10^140 years**: real-world RSA is safe against these attacks. Only a large quantum computer running **Shor's algorithm** would factor n in polynomial time.
- **Bonus:** encrypting letter by letter, as in this project, is itself a weakness. Each letter always gives the same number, so encrypting the 26 letters with the public key reveals any message instantly, whatever the key size (`codebook_attack`). This is why real RSA adds random padding (OAEP) before encrypting.

| | |
|---|---|
| ![Frequency analysis](figures/caesar_frequency_attack.png) | ![Brute force](figures/caesar_brute_force.png) |
| ![Pollard's rho success rate](figures/rsa_pollard_success.png) | |

## How it works

**Caesar cipher.** Each letter of rank x (a = 0, …, z = 25) becomes x + k mod 26. There are only 26 possible keys.

**RSA.** Choose two primes p and q, set n = pq and φ(n) = (p − 1)(q − 1), pick e coprime with φ(n) (65,537 in practice) and compute d, the inverse of e modulo φ(n).
- Public key (n, e): a letter of rank x is encrypted as y = x^e mod n.
- Private key d: x = y^d mod n. The proof relies on Fermat's little theorem (see the appendix of the [slides](docs/TIPE_slides_fr.pdf)).

**Attack.** Anyone who factors n finds p and q, hence φ(n) and d: the whole security of RSA rests on the difficulty of factoring.
- *Trial division* tests every odd divisor up to √n.
- *Pollard's rho* iterates x ↦ x² + c mod n. Modulo the unknown factor p, this sequence lives in a finite set, so it eventually cycles (the shape of the letter ρ). Floyd's "tortoise and hare" detects the cycle: x moves one step, y two steps, and gcd(|x − y|, n) reveals p as soon as x ≡ y (mod p). By the birthday paradox, this takes about √p ≈ n^¼ steps.

## Getting started

```bash
pip install -r requirements.txt
python -m pytest                               # 108 tests
python experiments/run_experiments.py --quick  # all experiments in about 1 minute (saved to figures_quick/)
```

The full run (`python experiments/run_experiments.py`, about 10 minutes) regenerates `figures/` and the raw results in `results/`; `--plot-only` redraws the figures from `results/`. Timings were measured on a standard x86_64 machine with Python 3.13: absolute times vary from one computer to another, growth rates do not.

```python
from cryptanalysis import rsa, attacks

public, private = rsa.generate_keys(64)            # 64-bit modulus n
cipher = rsa.encrypt("bonjour", public)
attacks.break_rsa(cipher, public)                  # 'bonjour', using the public key only
```

## Project structure

```
cryptanalysis/
  words.py        French word list: random words and texts, dictionary lookup
  caesar.py       Caesar cipher, frequency analysis, brute force
  rsa.py          Key generation (Miller-Rabin primes), encryption, decryption
  attacks.py      Trial division, Pollard's rho, full attack, codebook attack
experiments/      run_experiments.py: every experiment and figure
tests/            Unit tests (pytest)
data/             words_fr.tsv: 77,824 French words with their frequency
scripts/          build_wordlist.py: rebuilds the word list from Lexique
figures/          Generated figures
results/          Raw results (CSV)
docs/             Original TIPE slides (in French)
```

## Changes since the original TIPE (2025)

The code was rewritten and every experiment was run again:
- **RSA encryption and decryption fixed**: they did not invert each other, and decryption computed y^d without reducing modulo n, which made it impossible beyond about 12 bits. Both now use modular exponentiation.
- **Key sizes corrected**: the slides' "number of bits of n" was in fact the size of p and q, so n was twice as large. The new figures use the real size of n.
- **Caesar frequency attack fixed**: the shift was computed as |rank(e) − rank(k)|, which fails whenever *e* is encrypted as a, b, c or d. It is now computed modulo 26 (the "original TIPE code" curve shows the difference).
- **Automatic brute force**: candidates are checked against the dictionary instead of being read manually.
- **More robust Pollard's rho**: it restarts with another constant instead of failing when the gcd equals n; time budget for experiments.
- Exact integer computations (φ(n), modular inverse), prime generation with Miller–Rabin, unit tests, reproducible experiments (fixed random seed).

## Credits

French word list derived from [Lexique 3.83](http://www.lexique.org) (New, Pallier et al.), distributed under the CC BY-SA 4.0 licence; `data/words_fr.tsv` is shared under the same licence.

**Samuel Placek**, MP computer science option, 2024–2025
