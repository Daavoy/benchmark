#!/usr/bin/env python3
"""Generates thesis figures and LaTeX tables from MQTT benchmark fixed runs."""
import sys, csv
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker
from pathlib import Path

HERE     = Path(__file__).resolve().parent
BENCH    = HERE / "mqtt_benchmark"
SUB_LOGS = BENCH / "subscriber" / "logs"
RESULTS  = BENCH / "results"
OUT      = HERE / "thesis_output"
sys.path.insert(0, str(BENCH / "data_analysis"))
import logs_parser as lp

OUT.mkdir(exist_ok=True)
(OUT / "figures").mkdir(exist_ok=True)
(OUT / "tables").mkdir(exist_ok=True)

BROKERS = ["hivemq", "emqx", "mosquitto", "rabbitmq", "nanomq"]
SIZES   = ["1kb", "35kb", "125kb", "1mb", "16mb"]
BL = {"hivemq": "HiveMQ", "emqx": "EMQX", "mosquitto": "Mosquitto",
      "rabbitmq": "RabbitMQ", "nanomq": "NanoMQ"}
SL = {"1kb": "1 KB", "35kb": "35 KB", "125kb": "125 KB", "1mb": "1 MB", "16mb": "16 MB"}
BC = {"hivemq": "#4878a8", "emqx": "#d1883a", "mosquitto": "#5a9e6f",
      "rabbitmq": "#b85450", "nanomq": "#7b6ba8"}
EXPECTED = 40_000


def load_lats(broker, size):
    d = SUB_LOGS / f"aut0_{broker}_{size}_fixed" / "qos0"
    if not d.exists():
        print(f"  MISSING: {d}"); return None
    print(f"  {broker} {size}...")
    logs = lp.get_sub_logs(str(d))
    if not logs:
        return None
    return lp.get_numpy_array_pub_sub(logs)["latency"]


def load_csv(broker, size):
    p = RESULTS / f"{size}_fixed" / f"{broker}_{size}_qos0.csv"
    if not p.exists():
        return None
    with open(p, newline="") as f:
        return list(csv.DictReader(f))


def pf(v):
    try:
        return float(v)
    except Exception:
        return float("nan")


# ── Load all data ──────────────────────────────────────────────────────────
print("Loading data...\n")
data = {}
for broker in BROKERS:
    data[broker] = {}
    for size in SIZES:
        lats = load_lats(broker, size)
        rows = load_csv(broker, size)
        e = {}
        if lats is None or len(lats) == 0:
            e = {"skip": True, "reason": "no data"}
        else:
            nr = len(lats)
            nl = EXPECTED - nr
            e = {
                "latencies": lats,
                "n_recv":    nr,
                "loss_pct":  max(0., nl / EXPECTED * 100),
                "mean_ms":   float(np.mean(lats)),
                "std_ms":    float(np.std(lats)),
                "median_ms": float(np.median(lats)),
                "p95_ms":    float(np.percentile(lats, 95)),
                "p99_ms":    float(np.percentile(lats, 99)),
                "max_ms":    float(np.max(lats)),
                "min_ms":    float(np.min(lats[lats >= 0])) if np.any(lats >= 0) else float("nan"),
            }
        if rows:
            cpus = [pf(r.get("broker_cpu_pct")) for r in rows]
            mems = [pf(r.get("broker_mem_pct")) for r in rows]
            e["cpu_mean"] = float(np.nanmean(cpus))
            e["mem_mean"] = float(np.nanmean(mems))
        else:
            e["cpu_mean"] = e["mem_mean"] = float("nan")
        e.setdefault("skip", False)
        data[broker][size] = e
        if not e["skip"]:
            print(f"  {broker:10} {size:6}: recv={e['n_recv']} loss={e['loss_pct']:.2f}% "
                  f"mean={e['mean_ms']:.2f}ms p95={e['p95_ms']:.2f}ms")


def tcell(b, s, f, fmt="{:.2f}"):
    e = data[b][s]
    if e.get("skip"):
        return r"\textemdash"
    v = e.get(f)
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return r"\textemdash"
    return fmt.format(v)


def lcell(b, s):
    e = data[b][s]
    if e.get("skip"):
        return r"\textemdash"
    v = e["loss_pct"]
    return "0" if v == 0. else f"{v:.2f}\\%"


# ── Matplotlib defaults ────────────────────────────────────────────────────
import matplotlib.transforms as mtransforms
plt.rcParams.update({
    "font.family": "serif", "font.size": 11, "axes.titlesize": 12,
    "axes.labelsize": 11, "xtick.labelsize": 10, "figure.dpi": 150,
})
xp = list(range(len(SIZES)))
xl = [SL[s] for s in SIZES]


def savefig(fig, stem):
    for ext in (".pdf", ".png"):
        fig.savefig(OUT / "figures" / f"{stem}{ext}", bbox_inches="tight")
    plt.close(fig)
    print(f"  fig: {stem}")


# ═══════════════════════════════════════════════════════════════════════════
# FIGURES
# ═══════════════════════════════════════════════════════════════════════════
print("\nGenerating figures...")

# Boxplots per payload size
for size in SIZES:
    vld = [(b, data[b][size]) for b in BROKERS if not data[b][size].get("skip")]
    if not vld:
        continue
    fig, ax = plt.subplots(figsize=(8, 4.5))
    arrays = [e["latencies"][e["latencies"] >= 0] for _, e in vld]
    bp = ax.boxplot(
        arrays,
        tick_labels=[BL[b] for b, _ in vld],
        patch_artist=True,
        medianprops=dict(color="black", linewidth=1.5),
        showfliers=False,
        whis=1.5,
    )
    for patch, (b, _) in zip(bp["boxes"], vld):
        patch.set_facecolor(BC[b])
        patch.set_alpha(0.75)
    ax.set_yscale("log")
    ylo, yhi = ax.get_ylim()
    ax.set_ylim(ylo, yhi * 2)
    ax.set_title(f"End-to-End Latency — {SL[size]} Payload (QoS 0)")
    ax.set_ylabel("Latency (ms, log scale)")
    ax.set_xlabel("Broker")
    ax.grid(axis="y", linestyle="--", alpha=0.3)
    ax.set_axisbelow(True)
    # Blended transform: x in data coords, y in axes fraction
    trans = mtransforms.blended_transform_factory(ax.transData, ax.transAxes)
    for i, (b, e) in enumerate(vld, 1):
        ax.text(i, 0.97, f"μ={e['mean_ms']:.1f}",
                ha="center", va="top", fontsize=8, color="dimgray",
                transform=trans)
    fig.tight_layout()
    savefig(fig, f"boxplot_{size}")

def _apply_log_scale(ax):
    """Apply log y-scale only when there is at least one positive finite value."""
    all_y = [p.get_ydata() for p in ax.get_lines()]
    has_positive = any(
        float(v) > 0
        for line_y in all_y
        for v in line_y
        if not (v != v)  # skip NaN
    )
    if has_positive:
        ax.set_yscale("log")
        ax.yaxis.set_major_formatter(matplotlib.ticker.ScalarFormatter())

# Mean latency line chart (log scale)
fig, ax = plt.subplots(figsize=(8, 4.5))
for b in BROKERS:
    y = [data[b][s]["mean_ms"] if not data[b][s].get("skip") else float("nan")
         for s in SIZES]
    ax.plot(xp, y, marker="o", label=BL[b], color=BC[b], linewidth=1.8, markersize=5)
ax.set_xticks(xp)
ax.set_xticklabels(xl)
ax.set_xlabel("Payload Size")
ax.set_ylabel("Mean Latency (ms)")
ax.set_title("Mean End-to-End Latency vs. Payload Size (QoS 0)")
ax.legend(loc="upper left", fontsize=9)
ax.grid(linestyle="--", alpha=0.5)
ax.set_axisbelow(True)
_apply_log_scale(ax)
fig.tight_layout()
savefig(fig, "mean_latency_vs_size")

# P95 latency line chart (log scale)
fig, ax = plt.subplots(figsize=(8, 4.5))
for b in BROKERS:
    y = [data[b][s]["p95_ms"] if not data[b][s].get("skip") else float("nan")
         for s in SIZES]
    ax.plot(xp, y, marker="s", label=BL[b], color=BC[b], linewidth=1.8, markersize=5)
ax.set_xticks(xp)
ax.set_xticklabels(xl)
ax.set_xlabel("Payload Size")
ax.set_ylabel("P95 Latency (ms)")
ax.set_title("95th-Percentile Latency vs. Payload Size (QoS 0)")
ax.legend(loc="upper left", fontsize=9)
ax.grid(linestyle="--", alpha=0.5)
ax.set_axisbelow(True)
_apply_log_scale(ax)
fig.tight_layout()
savefig(fig, "p95_latency_vs_size")

# 16 MB loss bar chart
fig, ax = plt.subplots(figsize=(7, 3.5))
losses = [data[b]["16mb"]["loss_pct"] if not data[b]["16mb"].get("skip") else 0
          for b in BROKERS]
bars = ax.bar([BL[b] for b in BROKERS], losses,
              color=[BC[b] for b in BROKERS], edgecolor="white")
for bar, v in zip(bars, losses):
    lbl = f"{v:.2f}%" if v > 0 else "0%"
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05, lbl,
            ha="center", va="bottom", fontsize=9, fontweight="bold",
            color="black" if v > 0 else "gray")
ax.set_ylabel("Message Loss (%)")
ax.set_title("Message Loss Rate — 16 MB Payload (QoS 0)")
ax.set_ylim(0, max(losses) * 1.4 + 0.5)
ax.grid(axis="y", linestyle="--", alpha=0.5)
ax.set_axisbelow(True)
fig.tight_layout()
savefig(fig, "loss_16mb")

# Mean latency heatmap
fig, ax = plt.subplots(figsize=(8, 4))
M = np.full((len(BROKERS), len(SIZES)), float("nan"))
for i, b in enumerate(BROKERS):
    for j, s in enumerate(SIZES):
        if not data[b][s].get("skip"):
            M[i, j] = data[b][s]["mean_ms"]
im = ax.imshow(np.where(np.isnan(M), np.nan, np.log10(M + 1e-9)),
               aspect="auto", cmap="YlOrRd")
ax.set_xticks(range(len(SIZES)))
ax.set_xticklabels([SL[s] for s in SIZES])
ax.set_yticks(range(len(BROKERS)))
ax.set_yticklabels([BL[b] for b in BROKERS])
ax.set_title("Mean Latency Heatmap — log10(ms) (QoS 0)")
for i in range(len(BROKERS)):
    for j in range(len(SIZES)):
        v = M[i, j]
        txt = f"{v:.1f}" if not np.isnan(v) else "N/A"
        col = "black" if (not np.isnan(v) and v < 500) else "white"
        ax.text(j, i, txt, ha="center", va="center", fontsize=9, color=col)
fig.colorbar(im, ax=ax, pad=0.02).set_label("log10(mean latency / ms)")
fig.tight_layout()
savefig(fig, "heatmap_mean_latency")

# CPU usage line chart
fig, ax = plt.subplots(figsize=(8, 4.5))
for b in BROKERS:
    y = [data[b][s].get("cpu_mean", float("nan"))
         if not data[b][s].get("skip") else float("nan")
         for s in SIZES]
    ax.plot(xp, y, marker="^", label=BL[b], color=BC[b], linewidth=1.8, markersize=5)
ax.set_xticks(xp)
ax.set_xticklabels(xl)
ax.set_xlabel("Payload Size")
ax.set_ylabel("CPU Usage (%)")
ax.set_title("Average Broker CPU Usage vs. Payload Size (QoS 0)")
ax.legend(loc="upper left", fontsize=9)
ax.grid(linestyle="--", alpha=0.5)
ax.set_axisbelow(True)
fig.tight_layout()
savefig(fig, "cpu_vs_size")

# Memory usage line chart — distinct linestyles so Mosquitto/NanoMQ (~0%) are separable
MEM_LS = {"hivemq": "-", "emqx": "-", "mosquitto": "--",
           "rabbitmq": "-", "nanomq": ":"}
fig, ax = plt.subplots(figsize=(8, 4.5))
for b in BROKERS:
    y = [data[b][s].get("mem_mean", float("nan"))
         if not data[b][s].get("skip") else float("nan")
         for s in SIZES]
    ax.plot(xp, y, marker="D", label=BL[b], color=BC[b], linewidth=1.8, markersize=5,
            linestyle=MEM_LS[b])
ax.set_xticks(xp)
ax.set_xticklabels(xl)
ax.set_xlabel("Payload Size")
ax.set_ylabel("Memory Usage (%)")
ax.set_title("Average Broker Memory Usage vs. Payload Size (QoS 0)")
ax.legend(loc="upper left", fontsize=9)
ax.grid(linestyle="--", alpha=0.5)
ax.set_axisbelow(True)
fig.tight_layout()
savefig(fig, "mem_vs_size")


# ═══════════════════════════════════════════════════════════════════════════
# LATEX TABLES
# ═══════════════════════════════════════════════════════════════════════════
print("\nGenerating LaTeX tables...")


def wtab(name, rows):
    (OUT / "tables" / f"{name}.tex").write_text("\n".join(rows))
    print(f"  tab: {name}.tex")


def tabhead(caption, label, cols):
    return [
        r"\begin{table}[ht]", r"\centering",
        f"\\caption{{{caption}}}",
        f"\\label{{{label}}}",
        f"\\begin{{tabular}}{{{cols}}}",
        r"\toprule",
    ]


def tabfoot():
    return [r"\bottomrule", r"\end{tabular}", r"\end{table}"]


# Loss summary
r = tabhead(r"Message loss rate (\%) per broker and payload size (QoS~0, 10 executions). "
            r"A dash indicates the run was incomplete.", "tab:loss-summary", "lrrrrr")
r += [r"Broker & 1~KB & 35~KB & 125~KB & 1~MB & 16~MB \\", r"\midrule"]
for b in BROKERS:
    r.append(" & ".join([BL[b]] + [lcell(b, s) for s in SIZES]) + r" \\")
r += tabfoot()
wtab("loss_summary", r)

# Mean latency summary
r = tabhead(r"Mean end-to-end latency (ms) per broker and payload size (QoS~0).",
            "tab:mean-latency-summary", "lrrrrr")
r += [r"Broker & 1~KB & 35~KB & 125~KB & 1~MB & 16~MB \\", r"\midrule"]
for b in BROKERS:
    r.append(" & ".join([BL[b]] + [tcell(b, s, "mean_ms") for s in SIZES]) + r" \\")
r += tabfoot()
wtab("mean_latency_summary", r)

# P95 latency summary
r = tabhead(r"95th-percentile (P95) latency (ms) per broker and payload size (QoS~0).",
            "tab:p95-latency-summary", "lrrrrr")
r += [r"Broker & 1~KB & 35~KB & 125~KB & 1~MB & 16~MB \\", r"\midrule"]
for b in BROKERS:
    r.append(" & ".join([BL[b]] + [tcell(b, s, "p95_ms") for s in SIZES]) + r" \\")
r += tabfoot()
wtab("p95_latency_summary", r)

# Per-size detail tables
for size in SIZES:
    r = tabhead(
        f"Latency statistics for {SL[size]} payload (QoS~0, 10 executions, "
        r"40\,000 expected messages). All latency values in ms. "
        r"Min is the smallest non-negative observed latency; a small number of "
        r"negative values caused by sub-millisecond clock jitter are excluded.",
        f"tab:stats-{size}", "lrrrrrrrr")
    r += [r"Broker & Received & Loss\,\% & Min & Mean & Std\,Dev & Median & P95 & Max \\", r"\midrule"]
    for b in BROKERS:
        e = data[b][size]
        if e.get("skip"):
            row = [BL[b]] + [r"\textemdash"] * 8
        else:
            row = [BL[b], f"{e['n_recv']:,}", lcell(b, size),
                   f"{e['min_ms']:.2f}", f"{e['mean_ms']:.2f}", f"{e['std_ms']:.2f}",
                   f"{e['median_ms']:.2f}", f"{e['p95_ms']:.2f}", f"{e['max_ms']:.2f}"]
        r.append(" & ".join(row) + r" \\")
    r += tabfoot()
    wtab(f"stats_{size}", r)

# Resource summary (memory only — CPU from docker stats is a single end-of-run
# snapshot and systematically underestimates bursty async brokers like NanoMQ)
r = tabhead(r"Average broker container memory usage (\%) per payload size (QoS~0). "
            r"Measured as a single \texttt{docker stats} snapshot at the end of each "
            r"execution and averaged over 10 executions.",
            "tab:resource-summary", "l" + "r" * len(SIZES))
r += [r"Broker & " + " & ".join(SL[s] for s in SIZES) + r" \\", r"\midrule"]
for b in BROKERS:
    def rv(b, s, k):
        v = data[b][s].get(k, float("nan"))
        return f"{v:.1f}" if not np.isnan(v) else r"\textemdash"
    r.append(f"{BL[b]} & " + " & ".join(rv(b, s, "mem_mean") for s in SIZES) + r" \\")
r += tabfoot()
wtab("resource_summary", r)

# ── Final summary ──────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print(f"{'Broker':10} {'Size':6} {'Recv':>7} {'Loss%':>7} "
      f"{'Mean':>8} {'Std':>8} {'Median':>8} {'P95':>8}")
print("-" * 70)
for broker in BROKERS:
    for size in SIZES:
        e = data[broker][size]
        if e.get("skip"):
            print(f"{BL[broker]:10} {size:6}  SKIPPED: {e.get('reason', '')}")
        else:
            print(f"{BL[broker]:10} {size:6} {e['n_recv']:>7} {e['loss_pct']:>7.2f} "
                  f"{e['mean_ms']:>8.2f} {e['std_ms']:>8.2f} "
                  f"{e['median_ms']:>8.2f} {e['p95_ms']:>8.2f}")

nf = len(list((OUT / "figures").glob("*")))
nt = len(list((OUT / "tables").glob("*")))

