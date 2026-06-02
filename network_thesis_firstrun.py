#!/usr/bin/env python3
"""
Network analysis for the PRE-FIXED (first) benchmark runs.

Covers all payload sizes 1 KB – 16 MB. 16 MB first-run PCAPs are .pcap.gz;
run build_16mb_cache.py first to build their caches (tshark extraction is
done once, results are cached, then loaded here without memory pressure).

Generates:
  - Cached TCP metrics for each first-run PCAP (reuses existing cache where possible)
  - Stacked RTT P95 heatmaps: first run vs second run (all sizes)
  - CONNACK-fix effect figure (HiveMQ RTT P95 before/after per size)
  - Retransmission rate comparison (first run vs second run)
  - Comparison LaTeX table
"""
import gc, json, subprocess, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from pathlib import Path

TSHARK  = "tshark"
HERE    = Path(__file__).resolve().parent
BENCH   = HERE / "mqtt_benchmark"
RESULTS = BENCH / "results"
OUT     = HERE / "thesis_output"

(OUT / "figures").mkdir(exist_ok=True)
(OUT / "tables").mkdir(exist_ok=True)

BROKERS      = ["hivemq", "emqx", "mosquitto", "rabbitmq", "nanomq"]
SIZES        = ["1kb", "35kb", "125kb", "1mb", "16mb"]
SIZES_ALL    = SIZES
BL = {"hivemq": "HiveMQ", "emqx": "EMQX", "mosquitto": "Mosquitto",
      "rabbitmq": "RabbitMQ", "nanomq": "NanoMQ"}
SL = {"1kb": "1 KB", "35kb": "35 KB", "125kb": "125 KB", "1mb": "1 MB", "16mb": "16 MB"}
BC = {"hivemq": "#1f77b4", "emqx": "#ff7f0e", "mosquitto": "#2ca02c",
      "rabbitmq": "#d62728", "nanomq": "#9467bd"}

plt.rcParams.update({
    "font.family": "serif", "font.size": 11, "axes.titlesize": 12,
    "axes.labelsize": 11, "xtick.labelsize": 10, "figure.dpi": 150,
})


def savefig(fig, stem):
    for ext in (".pdf", ".png"):
        fig.savefig(OUT / "figures" / f"{stem}{ext}", bbox_inches="tight")
    plt.close(fig)
    print(f"  fig: {stem}")


# ── PCAP discovery ────────────────────────────────────────────────────────────

def find_pcap_first(broker, size):
    cap_dir = RESULTS / size / "captures"
    if not cap_dir.exists():
        return None
    # Prefer _s200.pcap (already snaplen-trimmed, smaller, no decompression)
    s200 = sorted(cap_dir.glob(f"{broker}_{size}_qos0_*_s200.pcap"))
    if s200:
        return s200[0]
    gz = sorted(cap_dir.glob(f"{broker}_{size}_qos0_*.pcap.gz"))
    gz = [p for p in gz if p.stat().st_size > 0]
    return gz[0] if gz else None


def find_pcap_fixed(broker, size):
    cap_dir = RESULTS / f"{size}_fixed" / "captures"
    if not cap_dir.exists():
        return None
    s200 = sorted(cap_dir.glob(f"{broker}_{size}_qos0_*_s200.pcap"))
    if s200:
        return s200[0]
    orig = sorted(cap_dir.glob(f"{broker}_{size}_qos0_*.pcap"))
    return orig[0] if orig else None


# ── Cache helpers ─────────────────────────────────────────────────────────────

def _cache_paths(pcap):
    p = Path(pcap)
    if p.suffix == ".gz":
        base = p.parent / p.with_suffix("").with_suffix("").name
    else:
        base = p.with_suffix("")
    return base.with_suffix(".cache.json"), base.with_suffix(".cache.npz")


def load_cache(pcap):
    jpath, _ = _cache_paths(pcap)
    if not jpath.exists():
        return None
    with open(jpath) as f:
        return json.load(f)


def save_cache(pcap, stats):
    jpath, npath = _cache_paths(pcap)
    scalars = {k: v for k, v in stats.items()
               if k not in ("rtt_arr", "ovh_arr", "timeline")}
    with open(jpath, "w") as f:
        json.dump(scalars, f)
    np.savez_compressed(npath,
                        rtt_arr=stats["rtt_arr"].astype(np.float32),
                        ovh_arr=np.array([], dtype=np.float32))


def load_cache_fixed(broker, size):
    pcap = find_pcap_fixed(broker, size)
    if pcap is None:
        return None
    jpath = pcap.with_suffix("").with_suffix(".cache.json")
    if not jpath.exists():
        jpath = pcap.parent / (pcap.stem.replace("_s200", "") + ".cache.json")
    if not jpath.exists():
        return None
    with open(jpath) as f:
        return json.load(f)


# ── tshark extraction (mirrors network_thesis.py exactly) ────────────────────

def extract_all(pcap):
    cmd = [
        TSHARK, "-r", str(pcap),
        "-Y", "tcp.port == 1883",
        "-T", "fields", "-E", "separator=\t",
        "-e", "frame.time_epoch",
        "-e", "tcp.stream",
        "-e", "tcp.len",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "tcp.flags.reset",
        "-e", "tcp.analysis.retransmission",
        "-e", "tcp.analysis.zero_window",
        "-e", "tcp.analysis.ack_rtt",
        "-e", "mqtt.msgtype",
    ]
    t_min = t_max = None
    total_bytes = retrans = zero_win = resets = pub_count = n_packets = 0
    rtt_list = []

    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          text=True, bufsize=1 << 20) as proc:
        for raw in proc.stdout:
            parts = raw.rstrip("\n").split("\t")
            if len(parts) < 10:
                continue
            try:
                ts = float(parts[0])
            except ValueError:
                continue
            t_min = ts if t_min is None else t_min
            t_max = ts
            try:
                total_bytes += int(parts[2]) if parts[2] else 0
            except ValueError:
                pass
            if parts[6]:
                retrans += 1
            if parts[7]:
                zero_win += 1
            if parts[5] == "1":
                resets += 1
            if parts[8]:
                try:
                    rtt_list.append(float(parts[8]) * 1000)
                except ValueError:
                    pass
            if parts[9] == "3":
                pub_count += 1
            n_packets += 1

    duration = (t_max - t_min) if (t_min and t_max) else 1.0
    rtt_arr = np.array(rtt_list, dtype=np.float32)

    def pct(arr, q):
        pos = arr[arr > 0]
        return round(float(np.percentile(pos, q)), 3) if len(pos) else float("nan")

    return {
        "duration_s":         round(duration, 1),
        "total_bytes":        total_bytes,
        "n_packets":          n_packets,
        "mqtt_publishes":     pub_count,
        "throughput_KB/s":    round(total_bytes / 1024 / max(duration, 1), 1),
        "rtt_p50_ms":         pct(rtt_arr, 50),
        "rtt_p95_ms":         pct(rtt_arr, 95),
        "rtt_p99_ms":         pct(rtt_arr, 99),
        "retransmissions":    retrans,
        "retrans_rate_%":     round(100 * retrans / max(n_packets, 1), 3),
        "zero_window_events": zero_win,
        "tcp_resets":         resets,
        "rtt_arr":            rtt_arr[rtt_arr > 0],
        "ovh_arr":            np.array([], dtype=np.float32),
    }


# ── Load first-run data (1KB–1MB only) ───────────────────────────────────────

print("Loading first-run network data (1 KB – 1 MB)...\n")
first = {}
for broker in BROKERS:
    first[broker] = {}
    for size in SIZES:
        pcap = find_pcap_first(broker, size)
        if pcap is None:
            print(f"  MISSING: {broker} {size}")
            first[broker][size] = {"skip": True}
            continue

        cached = load_cache(pcap)
        if cached:
            print(f"  [cache] {broker:10} {size:6}  "
                  f"rtt_p95={cached.get('rtt_p95_ms','?')}ms  "
                  f"retrans={cached.get('retrans_rate_%','?')}%  "
                  f"zw={cached.get('zero_window_events','?')}")
            first[broker][size] = cached
        else:
            mb = pcap.stat().st_size / 1024 ** 2
            print(f"  [tshark] {broker:10} {size:6}  ({mb:.0f} MB) — extracting...",
                  flush=True)
            stats = extract_all(pcap)
            try:
                save_cache(pcap, stats)
                print(f"           cached → {pcap.name}")
            except OSError as e:
                print(f"           [warn] {e}")
            print(f"           pub={stats['mqtt_publishes']:,}  "
                  f"retrans={stats['retransmissions']:,}  "
                  f"zw={stats['zero_window_events']:,}  "
                  f"rtt_p95={stats['rtt_p95_ms']}ms")
            first[broker][size] = {k: v for k, v in stats.items()
                                   if k not in ("rtt_arr", "ovh_arr")}
            del stats
            gc.collect()
        first[broker][size].setdefault("skip", False)


# ── Load fixed-run data ───────────────────────────────────────────────────────

fixed = {}
for broker in BROKERS:
    fixed[broker] = {}
    for size in SIZES_ALL:
        d = load_cache_fixed(broker, size)
        fixed[broker][size] = d if d else {"skip": True}
        if d:
            fixed[broker][size].setdefault("skip", False)


def fv(run, b, s, k, default=float("nan")):
    e = run[b].get(s, {"skip": True})
    if e.get("skip"):
        return default
    v = e.get(k, default)
    return float("nan") if v is None else float(v)


# ── Summary printout ──────────────────────────────────────────────────────────

print("\n" + "=" * 88)
print(f"{'':22}  {'── FIRST RUN ──':>32}   {'── FIXED RUN ──':>32}")
print(f"{'Broker':10} {'Size':6}  {'P95_RTT':>8} {'Retrans%':>8} {'ZeroWin':>8}"
      f"   {'P95_RTT':>8} {'Retrans%':>8} {'ZeroWin':>8}")
print("-" * 88)
for b in BROKERS:
    for s in SIZES:
        def fmt(v, f="{:.3f}"): return f.format(v) if not np.isnan(v) else "—"
        print(f"{BL[b]:10} {s:6}  "
              f"{fmt(fv(first,b,s,'rtt_p95_ms')):>8} "
              f"{fmt(fv(first,b,s,'retrans_rate_%')):>8} "
              f"{fmt(fv(first,b,s,'zero_window_events'),'{:.0f}'):>8}"
              f"   "
              f"{fmt(fv(fixed,b,s,'rtt_p95_ms')):>8} "
              f"{fmt(fv(fixed,b,s,'retrans_rate_%')):>8} "
              f"{fmt(fv(fixed,b,s,'zero_window_events'),'{:.0f}'):>8}")


# ═══════════════════════════════════════════════════════════════════════════════
# FIGURES
# ═══════════════════════════════════════════════════════════════════════════════
print("\nGenerating comparison figures...")


# Figure C1: Stacked RTT P95 heatmaps (first run top, second run bottom)
fig, axes = plt.subplots(2, 1, figsize=(10, 7.5), constrained_layout=True)
vmin, vmax = np.log10(0.05), np.log10(5)   # 0.05–5 ms range covers the comparison

for ax, run, title in [(axes[0], first, "First Run (pre-fix)"),
                       (axes[1], fixed, "Second Run")]:
    M = np.full((len(BROKERS), len(SIZES)), float("nan"))
    for i, b in enumerate(BROKERS):
        for j, s in enumerate(SIZES):
            v = fv(run, b, s, "rtt_p95_ms")
            if not np.isnan(v):
                M[i, j] = v
    logM = np.where(np.isnan(M), np.nan, np.log10(np.clip(M, 1e-3, None)))
    im = ax.imshow(logM, aspect="auto", cmap="RdYlGn_r", vmin=vmin, vmax=vmax)
    ax.set_xticks(range(len(SIZES)))
    ax.set_xticklabels([SL[s] for s in SIZES], fontsize=10)
    ax.set_yticks(range(len(BROKERS)))
    ax.set_yticklabels([BL[b] for b in BROKERS], fontsize=10)
    ax.set_title(title, fontsize=12)
    for i in range(len(BROKERS)):
        for j in range(len(SIZES)):
            v = M[i, j]
            txt = f"{v:.2f}" if not np.isnan(v) else "—"
            col = "white" if (not np.isnan(v) and v >= 2) else "black"
            ax.text(j, i, txt, ha="center", va="center", fontsize=9.5, color=col)

fig.colorbar(im, ax=axes.ravel().tolist(), pad=0.02, fraction=0.015,
             label="log10(RTT P95 / ms)", shrink=0.9, aspect=30)
fig.suptitle("TCP ACK RTT P95 (ms) — First Run vs. Second Run, All Payload Sizes (QoS 0)",
             fontsize=11)
savefig(fig, "net_compare_rtt_heatmap")


# Figure C2: HiveMQ CONNACK-fix effect — RTT P95 before/after, all sizes
fig, ax = plt.subplots(figsize=(7, 4.5))
x = np.arange(len(SIZES))
w = 0.35
before = [fv(first, "hivemq", s, "rtt_p95_ms") for s in SIZES]
after  = [fv(fixed,  "hivemq", s, "rtt_p95_ms") for s in SIZES]
b1 = ax.bar(x - w/2, before, w,
            label="First run (no CONNACK wait)", color="#d62728", alpha=0.85)
b2 = ax.bar(x + w/2, after,  w,
            label="Second run (CONNACK wait loop)", color="#1f77b4", alpha=0.85)

ymax = max(v for v in before + after if not np.isnan(v)) * 1.30
ax.set_ylim(0, ymax)
for bar, v in zip(list(b1) + list(b2), before + after):
    if not np.isnan(v):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + ymax * 0.02,
                f"{v:.2f}", ha="center", va="bottom", fontsize=8.5)

ax.set_xticks(x)
ax.set_xticklabels([SL[s] for s in SIZES])
ax.set_ylabel("TCP ACK RTT P95 (ms)")
ax.set_xlabel("Payload Size")
ax.set_title("HiveMQ — RTT P95 Before and After CONNACK Wait-Loop Fix (QoS 0)")
ax.legend(fontsize=9)
ax.grid(axis="y", linestyle="--", alpha=0.5)
ax.set_axisbelow(True)
fig.tight_layout()
savefig(fig, "net_compare_hivemq_connack")


# Figure C3: Retransmission rate — first vs fixed, side by side
fig, axes = plt.subplots(1, 2, figsize=(12, 4.5), sharey=True)
for ax, run, title in [(axes[0], first, "First Run"), (axes[1], fixed, "Second Run")]:
    for b in BROKERS:
        y = [fv(run, b, s, "retrans_rate_%") for s in SIZES]
        ax.plot(range(len(SIZES)), y, marker="s",
                label=BL[b], color=BC[b], linewidth=1.8, markersize=5)
    ax.set_xticks(range(len(SIZES)))
    ax.set_xticklabels([SL[s] for s in SIZES])
    ax.set_xlabel("Payload Size")
    ax.set_ylabel("Retransmission Rate (%)" if ax is axes[0] else "")
    ax.set_title(title, fontsize=11)
    ax.legend(fontsize=8)
    ax.grid(linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)
    ax.set_ylim(bottom=0)

fig.suptitle("TCP Retransmission Rate — First Run vs. Second Run (All Payload Sizes, QoS 0)",
             fontsize=11)
fig.tight_layout()
savefig(fig, "net_compare_retrans")


# ═══════════════════════════════════════════════════════════════════════════════
# LATEX COMPARISON TABLE
# ═══════════════════════════════════════════════════════════════════════════════
print("\nGenerating comparison table...")


def ncell(run, b, s, k, fmt="{:.3f}"):
    v = fv(run, b, s, k)
    return r"\textemdash" if np.isnan(v) else fmt.format(v)


size_header = " & ".join(SL[s] for s in SIZES)
rows = [
    r"\begin{table}[ht]",
    r"\centering",
    r"\caption{TCP ACK RTT P95 (ms) and retransmission rate (\%) comparing the first "
    r"(pre-fix) and second benchmark runs at all five payload sizes (QoS~0). "
    r"Pre-fixed 16~MB captures are from partial tshark passes (stall-detected); "
    r"Mosquitto pre-fixed 16~MB data is unavailable (empty capture, shown as \textemdash). "
    r"HiveMQ's RTT P95 at 35~KB drops from 3.38~ms to 0.35~ms --- a "
    r"${\sim}10\,\times$ reduction from the CONNACK wait-loop correction. "
    r"At 16~MB the effect reverses: Docker resource limits applied in the second run "
    r"increase RTT for all brokers, masking the CONNACK improvement at that size. "
    r"EMQX's elevated retransmission rate at 125~KB disappears after "
    r"Docker resource limits are applied.}",
    r"\label{tab:net-firstrun-compare}",
    r"\begin{tabular}{ll" + "r" * len(SIZES) + "r" * len(SIZES) + "}",
    r"\toprule",
    (r"\multicolumn{2}{l}{} & \multicolumn{" + str(len(SIZES)) + r"}{c}{First Run} & "
     r"\multicolumn{" + str(len(SIZES)) + r"}{c}{Second Run} \\"),
    (r"\cmidrule(lr){3-" + str(2 + len(SIZES)) + r"}"
     r"\cmidrule(lr){" + str(3 + len(SIZES)) + r"-" + str(2 + 2*len(SIZES)) + r"}"),
    r"Broker & Metric & " + size_header + " & " + size_header + r" \\",
    r"\midrule",
]
for b in BROKERS:
    p95_f = [ncell(first, b, s, "rtt_p95_ms") for s in SIZES]
    rt_f  = [ncell(first, b, s, "retrans_rate_%") for s in SIZES]
    p95_x = [ncell(fixed, b, s, "rtt_p95_ms") for s in SIZES]
    rt_x  = [ncell(fixed, b, s, "retrans_rate_%") for s in SIZES]
    rows.append(f"{BL[b]} & RTT P95 & "
                + " & ".join(p95_f) + " & " + " & ".join(p95_x) + r" \\")
    rows.append(r" & Retrans\,\% & "
                + " & ".join(rt_f) + " & " + " & ".join(rt_x) + r" \\")
    rows.append(r"\addlinespace")

rows += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
(OUT / "tables" / "net_firstrun_compare.tex").write_text("\n".join(rows))
print("  tab: net_firstrun_compare.tex")

print(f"\nOutput: {OUT}")
print("  3 comparison figures  |  1 comparison table")
