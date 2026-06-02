#!/usr/bin/env python3
"""
Supplementary thesis statistics:
  - Empirical CDF plots per payload size
  - Kruskal-Wallis + pairwise Mann-Whitney U significance tests
  - Temporal stability (rolling P95 over time) at 1 MB and 16 MB
  - Coefficient of Variation summary table
"""
import sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from pathlib import Path
from scipy import stats as scipy_stats

HERE     = Path(__file__).resolve().parent
BENCH    = HERE / "mqtt_benchmark"
SUB_LOGS = BENCH / "subscriber" / "logs"
OUT      = HERE / "thesis_output"
sys.path.insert(0, str(BENCH / "data_analysis"))
import logs_parser as lp

(OUT / "figures").mkdir(exist_ok=True)
(OUT / "tables").mkdir(exist_ok=True)

BROKERS = ["hivemq", "emqx", "mosquitto", "rabbitmq", "nanomq"]
SIZES   = ["1kb", "35kb", "125kb", "1mb", "16mb"]
BL = {"hivemq": "HiveMQ", "emqx": "EMQX", "mosquitto": "Mosquitto",
      "rabbitmq": "RabbitMQ", "nanomq": "NanoMQ"}
BC = {"hivemq": "#1f77b4", "emqx": "#ff7f0e", "mosquitto": "#2ca02c",
      "rabbitmq": "#d62728", "nanomq": "#9467bd"}
SL = {"1kb": "1 KB", "35kb": "35 KB", "125kb": "125 KB", "1mb": "1 MB", "16mb": "16 MB"}

plt.rcParams.update({
    "font.family": "serif", "font.size": 11, "axes.titlesize": 12,
    "axes.labelsize": 11, "xtick.labelsize": 10, "figure.dpi": 150,
})


def savefig(fig, stem):
    for ext in (".pdf", ".png"):
        fig.savefig(OUT / "figures" / f"{stem}{ext}", bbox_inches="tight")
    plt.close(fig)
    print(f"  fig: {stem}")


# ── Load latency arrays + full structured arrays (for timestamps) ──────────
print("Loading data...\n")
lats  = {}   # broker -> size -> np.ndarray of latency floats
sarrs = {}   # broker -> size -> full structured array (has .timestamp field)

for broker in BROKERS:
    lats[broker]  = {}
    sarrs[broker] = {}
    for size in SIZES:
        d = SUB_LOGS / f"aut0_{broker}_{size}_fixed" / "qos0"
        if not d.exists():
            print(f"  MISSING: {d}")
            lats[broker][size]  = None
            sarrs[broker][size] = None
            continue
        print(f"  loading {broker} {size}...")
        logs = lp.get_sub_logs(str(d))
        if not logs:
            lats[broker][size]  = None
            sarrs[broker][size] = None
            continue
        arr = lp.get_numpy_array_pub_sub(logs)
        sarrs[broker][size] = arr
        lats[broker][size]  = arr["latency"].astype(float)


# ═══════════════════════════════════════════════════════════════════════════
# 1. EMPIRICAL CDF PLOTS  (one figure per payload size)
# ═══════════════════════════════════════════════════════════════════════════
print("\nGenerating CDF figures...")

for size in SIZES:
    fig, ax = plt.subplots(figsize=(7, 4.5))
    any_plotted = False
    for broker in BROKERS:
        lat = lats[broker][size]
        if lat is None or len(lat) == 0:
            continue
        sorted_lat = np.sort(lat)
        cdf = np.arange(1, len(sorted_lat) + 1) / len(sorted_lat)
        ax.plot(sorted_lat, cdf, label=BL[broker], color=BC[broker],
                linewidth=1.6, alpha=0.9)
        any_plotted = True

    if not any_plotted:
        plt.close(fig)
        continue

    ax.set_xscale("log")
    ax.set_xlabel("End-to-End Latency (ms, log scale)")
    ax.set_ylabel("Cumulative Probability")
    ax.set_title(f"Latency CDF — {SL[size]} Payload (QoS 0)")
    ax.set_ylim(0, 1.02)
    ax.axhline(0.95, color="#d62728", linestyle="--", linewidth=1.5, alpha=0.9,
               label="P95", zorder=3)
    ax.axhline(0.99, color="#1f77b4", linestyle=(0, (4, 1, 1, 1)), linewidth=1.5, alpha=0.9,
               label="P99", zorder=3)
    ax.legend(fontsize=9, loc="lower right")
    ax.grid(True, which="major", linestyle=":", alpha=0.4)
    ax.set_axisbelow(True)
    fig.tight_layout()
    savefig(fig, f"cdf_{size}")


# ═══════════════════════════════════════════════════════════════════════════
# 2. STATISTICAL SIGNIFICANCE TESTS
#    Kruskal-Wallis per size, then pairwise Mann-Whitney U (Bonferroni)
# ═══════════════════════════════════════════════════════════════════════════
print("\nRunning significance tests...")

N_PAIRS = 10  # C(5,2)
ALPHA   = 0.05
ALPHA_B = ALPHA / N_PAIRS   # Bonferroni-corrected threshold

kw_results  = {}   # size -> (H, p)
mwu_results = {}   # size -> {(b1,b2): p}

for size in SIZES:
    groups = [(b, lats[b][size]) for b in BROKERS
              if lats[b][size] is not None and len(lats[b][size]) > 0]
    if len(groups) < 2:
        kw_results[size]  = None
        mwu_results[size] = {}
        continue

    H, p = scipy_stats.kruskal(*[g[1] for g in groups])
    kw_results[size] = (H, p)
    print(f"  KW {size}: H={H:.1f}  p={p:.2e}  (n_groups={len(groups)})")

    pairs = {}
    for i in range(len(groups)):
        for j in range(i + 1, len(groups)):
            b1, l1 = groups[i]
            b2, l2 = groups[j]
            stat, pv = scipy_stats.mannwhitneyu(l1, l2, alternative="two-sided")
            pairs[(b1, b2)] = pv
    mwu_results[size] = pairs


def sig_stars(p, alpha_b):
    if p < alpha_b / 10:
        return "***"
    if p < alpha_b:
        return "**"
    if p < ALPHA:
        return "*"
    return "ns"


# ── LaTeX table: Kruskal-Wallis summary ────────────────────────────────────
kw_lines = []
for size in SIZES:
    r = kw_results.get(size)
    if r is None:
        kw_lines.append(f"{SL[size]} & \\textemdash & \\textemdash \\\\")
    else:
        H, p = r
        ps = f"{p:.2e}".replace("e-0", "e-").replace("e+0", "e+")
        kw_lines.append(f"{SL[size]} & {H:.1f} & {ps} \\\\")

kw_tex = r"""\begin{table}[ht]
\centering
\caption{Kruskal-Wallis test results comparing end-to-end latency distributions
across all five brokers at each payload size (QoS~0).
A significant result ($p < 0.05$) indicates that at least one broker differs
from the others; subsequent pairwise tests (Table~\ref{tab:mwu}) identify which pairs.}
\label{tab:kruskal-wallis}
\begin{tabular}{lrr}
\toprule
Payload Size & $H$ statistic & $p$-value \\
\midrule
""" + "\n".join(kw_lines) + r"""
\bottomrule
\end{tabular}
\end{table}
"""
(OUT / "tables" / "stat_kruskal_wallis.tex").write_text(kw_tex)
print("  tab: stat_kruskal_wallis.tex")


# ── LaTeX table: pairwise Mann-Whitney U lower-triangle matrix per size ────
# Produce one table per size, collected into one .tex file
mwu_tex_parts = []
for size in SIZES:
    pairs = mwu_results.get(size, {})
    active = [b for b in BROKERS
              if lats[b][size] is not None and len(lats[b][size]) > 0]
    if len(active) < 2:
        continue

    short = {b: BL[b].replace("Mosquitto", "Mosq.").replace("RabbitMQ", "Rabbit") for b in active}
    header = " & " + " & ".join(f"\\rotatebox{{45}}{{{short[b]}}}" for b in active[:-1]) + r" \\"
    rows = []
    for i in range(1, len(active)):
        b2 = active[i]
        cells = []
        for j in range(i):
            b1 = active[j]
            p  = pairs.get((b1, b2), pairs.get((b2, b1)))
            cells.append("\\textemdash" if p is None else sig_stars(p, ALPHA_B))
        rows.append(short[b2] + " & " + " & ".join(cells) + r" \\")

    col_spec = "l" + "c" * (len(active) - 1)
    mwu_tex_parts.append(
        f"\\paragraph{{{SL[size]}}}\n"
        f"\\begin{{tabular}}{{{col_spec}}}\n"
        f"\\toprule\n"
        f"{header}\n"
        f"\\midrule\n"
        + "\n".join(rows) + "\n"
        + r"\bottomrule" + "\n"
        + r"\end{tabular}" + "\n"
    )

mwu_tex = (
    r"""\begin{table}[ht]
\centering
\caption{Pairwise Mann-Whitney U test significance for end-to-end latency
(QoS~0, Bonferroni-corrected threshold $\alpha/10 = 0.005$).
*** $p < 0.0005$;\; ** $p < 0.005$;\; * $p < 0.05$;\; ns not significant.}
\label{tab:mwu}
"""
    + "\n\\medskip\n\n".join(mwu_tex_parts)
    + r"""
\end{table}
"""
)
(OUT / "tables" / "stat_mwu.tex").write_text(mwu_tex)
print("  tab: stat_mwu.tex")

# Print pairwise summary to stdout
print()
for size in SIZES:
    pairs = mwu_results.get(size, {})
    if not pairs:
        continue
    print(f"  MWU {size} (Bonferroni α={ALPHA_B:.4f}):")
    for (b1, b2), p in pairs.items():
        print(f"    {BL[b1]:10} vs {BL[b2]:10}: p={p:.2e}  {sig_stars(p, ALPHA_B)}")


# ═══════════════════════════════════════════════════════════════════════════
# 3. TEMPORAL STABILITY — rolling P95 over message arrival time
#    Shown at 1 MB and 16 MB (the sizes where brokers diverge most).
# ═══════════════════════════════════════════════════════════════════════════
print("\nGenerating temporal stability figures...")


def rolling_p95(timestamps, latencies, window_s=30.0):
    """Return (bin_centres_s, p95_values) using a sliding window over time."""
    t0 = timestamps.min()
    t_rel = timestamps - t0
    duration = t_rel.max()
    step = window_s / 2
    centres, p95s = [], []
    t = window_s / 2
    while t <= duration:
        mask = (t_rel >= t - window_s / 2) & (t_rel < t + window_s / 2)
        if mask.sum() >= 10:
            centres.append(t)
            p95s.append(np.percentile(latencies[mask], 95))
        t += step
    return np.array(centres), np.array(p95s)


for size in ["1mb", "16mb"]:
    fsize = (9, 5.5) if size == "1mb" else (8, 4.5)
    fig, ax = plt.subplots(figsize=fsize)
    any_plotted = False
    for broker in BROKERS:
        arr = sarrs[broker][size]
        if arr is None or len(arr) == 0:
            continue

        try:
            ts   = arr["timestamp"].astype(float)
            lat  = arr["latency"].astype(float)
        except (ValueError, KeyError):
            continue

        # timestamps may be in ms or s; normalise to seconds
        if ts.mean() > 1e10:
            ts = ts / 1000.0

        centres, p95s = rolling_p95(ts, lat, window_s=30.0)
        if len(centres) < 3:
            continue

        ax.plot(centres / 60, p95s, label=BL[broker], color=BC[broker],
                linewidth=1.6, alpha=0.9)
        any_plotted = True

    if not any_plotted:
        plt.close(fig)
        continue

    if size == "1mb":
        ax.set_yscale("log")
        ax.yaxis.set_major_formatter(mticker.ScalarFormatter())
    ax.set_xlabel("Elapsed Time (minutes)")
    ax.set_ylabel("Latency P95 — 30 s window (ms, log scale)" if size == "1mb"
                  else "Latency P95 — 30 s window (ms)")
    ax.set_title(f"Temporal Stability of P95 Latency — {SL[size]} Payload (QoS 0)")
    ax.legend(fontsize=9)
    ax.grid(linestyle="--", alpha=0.4, which="major")
    ax.set_axisbelow(True)
    fig.tight_layout()
    savefig(fig, f"temporal_stability_{size}")


# ═══════════════════════════════════════════════════════════════════════════
# 4. COEFFICIENT OF VARIATION TABLE
# ═══════════════════════════════════════════════════════════════════════════
print("\nGenerating CoV table...")

cov_rows = []
for broker in BROKERS:
    cells = []
    for size in SIZES:
        lat = lats[broker][size]
        if lat is None or len(lat) == 0:
            cells.append(r"\textemdash")
        else:
            mean = lat.mean()
            cov  = lat.std() / mean if mean > 0 else float("nan")
            cells.append(f"{cov:.2f}")
    cov_rows.append(f"{BL[broker]} & " + " & ".join(cells) + r" \\")

cov_tex = r"""\begin{table}[ht]
\centering
\caption{Coefficient of variation (CoV = $\sigma/\mu$) of end-to-end latency
per broker and payload size (QoS~0). Values greater than 1 indicate that the
standard deviation exceeds the mean, signalling a heavy-tailed or multimodal
distribution.}
\label{tab:cov}
\begin{tabular}{lrrrrr}
\toprule
Broker & 1 KB & 35 KB & 125 KB & 1 MB & 16 MB \\
\midrule
""" + "\n".join(cov_rows) + r"""
\addlinespace
\bottomrule
\end{tabular}
\end{table}
"""
(OUT / "tables" / "stat_cov.tex").write_text(cov_tex)
print("  tab: stat_cov.tex")

# Print CoV to stdout for inspection
print()
print(f"{'Broker':12} " + " ".join(f"{s:>7}" for s in SIZES))
print("-" * 52)
for broker in BROKERS:
    vals = []
    for size in SIZES:
        lat = lats[broker][size]
        if lat is None or len(lat) == 0:
            vals.append("   —  ")
        else:
            cov = lat.std() / lat.mean()
            vals.append(f"{cov:7.2f}")
    print(f"{BL[broker]:12} " + " ".join(vals))

print(f"\nOutput: {OUT}")
print(f"  {len(list((OUT/'figures').glob('cdf_*.pdf')))} CDF figures")
print(f"  {len(list((OUT/'figures').glob('temporal_*.pdf')))} temporal-stability figures")
print("  3 LaTeX tables  (stat_kruskal_wallis.tex, stat_mwu.tex, stat_cov.tex)")
