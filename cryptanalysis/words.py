"""French word list (derived from Lexique 3.83) used to generate test messages."""
import random
from functools import lru_cache
from itertools import accumulate
from pathlib import Path

WORDS_FILE = Path(__file__).resolve().parent.parent / "data" / "words_fr.tsv"


@lru_cache(maxsize=1)
def load_words() -> dict[str, float]:
    """Return {word: frequency per million words} for all a-z French words."""
    words = {}
    with open(WORDS_FILE, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                continue
            word, freq = line.rstrip("\n").split("\t")
            words[word] = float(freq)
    return words


@lru_cache(maxsize=None)
def words_of_length(n: int) -> tuple[str, ...]:
    return tuple(w for w in load_words() if len(w) == n)


def is_word(word: str) -> bool:
    return word in load_words()


def random_word(n: int, rng: random.Random = random) -> str:
    """A word of exactly n letters, drawn uniformly from the dictionary."""
    candidates = words_of_length(n)
    if not candidates:
        raise ValueError(f"No French word of length {n} in the word list")
    return rng.choice(candidates)


@lru_cache(maxsize=1)
def _frequency_table() -> tuple[tuple[str, ...], list[float]]:
    words = load_words()
    return tuple(words), list(accumulate(words.values()))


def random_text(n_letters: int, rng: random.Random = random) -> str:
    """Realistic French text (words drawn by frequency, no spaces), cut to n_letters."""
    population, cum_weights = _frequency_table()
    text = ""
    while len(text) < n_letters:
        text += "".join(rng.choices(population, cum_weights=cum_weights, k=8))
    return text[:n_letters]
