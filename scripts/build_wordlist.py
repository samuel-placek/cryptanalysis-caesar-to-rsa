"""Build data/words_fr.tsv from the Lexique 3.83 database.

Lexique 3.83 (New, Pallier et al.) is available at http://www.lexique.org
under the CC BY-SA 4.0 licence. Download Lexique383.xlsb, then run:

    python scripts/build_wordlist.py path/to/Lexique383.xlsb

Only words made of the 26 lowercase letters a-z are kept (no accents, hyphens
or spaces), as in the original project. Each word comes with its frequency
(occurrences per million words, average of the film-subtitle and book corpora),
summed over its grammatical categories.
"""
import sys
from pathlib import Path

import pandas as pd

OUT = Path(__file__).resolve().parent.parent / "data" / "words_fr.tsv"


def main(xlsb_path: str) -> None:
    df = pd.read_excel(xlsb_path, engine="pyxlsb", usecols=["1_ortho", "9_freqfilms2", "10_freqlivres"])
    df = df.dropna(subset=["1_ortho"])
    df["word"] = df["1_ortho"].astype(str)
    df = df[df["word"].str.fullmatch(r"[a-z]+")]
    df["freq"] = (df["9_freqfilms2"].fillna(0) + df["10_freqlivres"].fillna(0)) / 2
    words = df.groupby("word")["freq"].sum().sort_index()
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("# French word list derived from Lexique 3.83 (www.lexique.org), CC BY-SA 4.0\n")
        f.write("# word<TAB>frequency per million words\n")
        for word, freq in words.items():
            f.write(f"{word}\t{freq:.2f}\n")
    print(f"{len(words)} words written to {OUT}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python scripts/build_wordlist.py path/to/Lexique383.xlsb")
    main(sys.argv[1])
