"""Run all experiments: raw results go to results/ (CSV), figures to figures/.

Usage (from the root of the repository):
    python experiments/run_experiments.py              # full run (about 10 minutes)
    python experiments/run_experiments.py --quick      # smaller run (about 1 minute), saved to *_quick/
    python experiments/run_experiments.py --plot-only  # redraw the figures from results/
"""
import argparse
import csv
import platform
import random
import statistics
import sys
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cryptanalysis import attacks, caesar, rsa, words  # noqa: E402

FIGURES, RESULTS = ROOT / "figures", ROOT / "results"
BLUE, RED, GREY = "#1f5fa8", "#c0392b", "#7f8c8d"
plt.rcParams.update({"figure.dpi": 130, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.alpha": 0.3, "font.size": 10})
BUDGET = 1.0   # seconds allowed per key in the success-rate experiment


# --- CSV helpers -----------------------------------------------------------------------

def save_csv(name, header, rows):
    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / f"{name}.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def load_csv(name):
    """Columns of results/<name>.csv as lists of floats."""
    with open(RESULTS / f"{name}.csv", newline="") as f:
        rows = list(csv.reader(f))[1:]
    return [list(map(float, col)) for col in zip(*rows)]


def pct(values):
    return [100 * v for v in values]


# --- Caesar: experiments ---------------------------------------------------------------

def original_guess_shift(cipher):
    """Shift computed as in the original TIPE code: abs(ord('e') - ord(k)).
    Wrong whenever the most frequent letter comes before 'e' in the alphabet."""
    counts = {c: cipher.count(c) for c in caesar.ALPHABET}
    most_common = max(counts, key=counts.get)
    return abs(ord("e") - ord(most_common))


def run_caesar_frequency(rng, trials):
    lengths = range(2, 16)
    rows = []
    for n in lengths:
        ok_fixed = ok_original = 0
        for _ in range(trials):
            word, k = words.random_word(n, rng), rng.randrange(1, 26)
            cipher = caesar.encrypt(word, k)
            ok_fixed += caesar.frequency_attack(cipher) == word
            ok_original += caesar.decrypt(cipher, original_guess_shift(cipher)) == word
        rows.append((n, ok_fixed / trials, ok_original / trials))
    save_csv("caesar_frequency_words", ["word_length", "success_fixed", "success_original_code"], rows)

    rows = []
    for n in (5, 10, 20, 30, 40, 50, 75, 100, 150, 200, 300):
        ok = 0
        for _ in range(trials):
            text, k = words.random_text(n, rng), rng.randrange(1, 26)
            ok += caesar.frequency_attack(caesar.encrypt(text, k)) == text
        rows.append((n, ok / trials))
    save_csv("caesar_frequency_texts", ["text_length", "success"], rows)


def run_caesar_brute_force(rng, trials):
    rows = []
    for n in range(2, 16):
        n_unique = n_ambiguous = 0
        for _ in range(trials):
            word, k = words.random_word(n, rng), rng.randrange(1, 26)
            candidates = caesar.brute_force_attack(caesar.encrypt(word, k))
            assert word in candidates          # the right word is always among the candidates
            n_unique += len(candidates) == 1
            n_ambiguous += len(candidates) > 1
        rows.append((n, n_unique / trials, n_ambiguous / trials))
    save_csv("caesar_brute_force", ["word_length", "unique_answer", "ambiguous"], rows)


# --- RSA: experiments ------------------------------------------------------------------

def time_factoring(factor, sizes, keys_per_size, rng, time_limit):
    rows = []
    for n_bits in sizes:
        times = []
        for _ in range(keys_per_size):
            public, private = rsa.generate_keys(n_bits, rng)
            start = time.perf_counter()
            p = factor(public.n, deadline=start + time_limit)
            times.append(time.perf_counter() - start)
            assert p in (private.p, private.q)
        rows.append((n_bits, statistics.median(times)))
        print(f"  {factor.__name__:15s} n = {n_bits:3d} bits: median {rows[-1][1]:.4f} s", flush=True)
    return rows


def run_rsa_factoring_time(rng, quick):
    keys = 3 if quick else 5
    save_csv("rsa_naive_time", ["n_bits", "median_seconds"],
             time_factoring(attacks.trial_division, range(16, 49 if quick else 57, 4), keys, rng, 120))
    save_csv("rsa_pollard_time", ["n_bits", "median_seconds"],
             time_factoring(attacks.pollard_rho, range(16, 81 if quick else 97, 4), keys, rng, 300))


def run_rsa_success_rate(rng, quick):
    keys = 5 if quick else 20
    rows = []
    for n_bits in range(40, 97 if quick else 105, 8 if quick else 4):
        ok = 0
        for _ in range(keys):
            public, _ = rsa.generate_keys(n_bits, rng)
            message = words.random_word(rng.randrange(4, 12), rng)
            try:
                ok += attacks.break_rsa(rsa.encrypt(message, public), public, time_limit=BUDGET) == message
            except attacks.Timeout:
                pass
        rows.append((n_bits, ok / keys))
        print(f"  success within {BUDGET:g} s, n = {n_bits:3d} bits: {100 * rows[-1][1]:.0f} %", flush=True)
    save_csv("rsa_pollard_success", ["n_bits", "success_rate"], rows)


# --- Figures -------------------------------------------------------------------------

def plot_caesar_frequency():
    lengths, fixed, original = load_csv("caesar_frequency_words")
    text_lengths, text_success = load_csv("caesar_frequency_texts")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4))
    ax1.plot(lengths, pct(fixed), "o-", color=BLUE, label="Fixed attack")
    ax1.plot(lengths, pct(original), "s--", color=GREY, label="Original TIPE code")
    ax1.set(xlabel="Word length (letters)", ylabel="Success rate (%)", ylim=(0, 100),
            title="Single French words")
    ax1.legend()
    ax2.plot(text_lengths, pct(text_success), "o-", color=BLUE)
    ax2.set(xlabel="Text length (letters)", ylabel="Success rate (%)", ylim=(0, 105),
            title="French text (words drawn by frequency)")
    fig.suptitle("Caesar cipher: frequency analysis (most frequent letter = 'e')", fontweight="bold")
    fig.tight_layout()
    fig.savefig(FIGURES / "caesar_frequency_attack.png")
    plt.close(fig)


def plot_caesar_brute_force():
    lengths, unique, ambiguous = load_csv("caesar_brute_force")
    fig, ax = plt.subplots(figsize=(8, 4.3))
    ax.bar(lengths, pct(unique), color=BLUE, label="One valid word: message recovered")
    ax.bar(lengths, pct(ambiguous), bottom=pct(unique), color=GREY, label="Several valid words: ambiguous")
    ax.set(xlabel="Word length (letters)", ylabel="Share of messages (%)", ylim=(0, 100),
           title="Caesar cipher: brute force over the 26 shifts + dictionary check")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.17), ncol=2, frameon=False)
    fig.tight_layout()
    fig.savefig(FIGURES / "caesar_brute_force.png")
    plt.close(fig)


def plot_rsa_factoring_time():
    naive_bits, naive = load_csv("rsa_naive_time")
    rho_bits, rho = load_csv("rsa_pollard_time")
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.semilogy(naive_bits, naive, "s-", color=RED, label="Naive method (trial division): O(√n)")
    ax.semilogy(rho_bits, rho, "o-", color=BLUE, label="Pollard's rho: O(n^¼)")
    ax.set(xlabel="Size of the modulus n (bits)", ylabel="Median time to factor n (s, log scale)",
           title="RSA: time needed to recover the private key")
    ax.legend()
    fig.tight_layout()
    fig.savefig(FIGURES / "rsa_factoring_time.png")
    plt.close(fig)


def plot_rsa_success_rate():
    sizes, rates = load_csv("rsa_pollard_success")
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot(sizes, pct(rates), "o-", color=BLUE)
    ax.set(xlabel="Size of the modulus n (bits)", ylabel="Messages decrypted (%)", ylim=(-3, 103),
           title=f"RSA: Pollard's rho attack with a {BUDGET:g}-second budget per key")
    fig.tight_layout()
    fig.savefig(FIGURES / "rsa_pollard_success.png")
    plt.close(fig)


def plot_all():
    FIGURES.mkdir(exist_ok=True)
    plot_caesar_frequency()
    plot_caesar_brute_force()
    plot_rsa_factoring_time()
    plot_rsa_success_rate()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true", help="smaller experiments (about 1 minute)")
    parser.add_argument("--plot-only", action="store_true", help="only redraw the figures from results/")
    args = parser.parse_args()
    if args.quick:   # keep the full results intact: quick runs go to separate folders
        global FIGURES, RESULTS
        FIGURES, RESULTS = ROOT / "figures_quick", ROOT / "results_quick"

    if not args.plot_only:
        rng = random.Random(2025)
        trials = 200 if args.quick else 1000
        print(f"Machine: {platform.processor() or platform.machine()} | Python {platform.python_version()}")
        print("Caesar: frequency analysis...")
        run_caesar_frequency(rng, trials)
        print("Caesar: brute force...")
        run_caesar_brute_force(rng, trials)
        print("RSA: factoring time...")
        run_rsa_factoring_time(rng, args.quick)
        print("RSA: success rate within a time budget...")
        run_rsa_success_rate(rng, args.quick)
    plot_all()
    print(f"Done. Figures in {FIGURES}, raw results in {RESULTS}")


if __name__ == "__main__":
    main()
