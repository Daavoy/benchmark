#!/usr/bin/env bash
# reproduce_thesis.sh — regenerate all thesis figures and LaTeX tables.
#
# Run from the repository root:
#   bash reproduce_thesis.sh
#
# Requirements: Python 3.9+, matplotlib, numpy, scipy, tshark (Wireshark CLI)
# First-time tshark extraction is slow for large PCAPs (16 MB: ~5-30 min each);
# subsequent runs are instant because results are cached next to the PCAP files.
#
# Output goes to thesis_output/figures/ and thesis_output/tables/.

set -euo pipefail
cd "$(dirname "$0")"

echo "=== Step 1/4: Latency, reliability, and resource-utilisation figures ==="
python3 thesis_analysis.py

echo ""
echo "=== Step 2/4: Statistical analysis (Kruskal-Wallis, MWU, CoV, CDF) ==="
python3 thesis_stats.py

echo ""
echo "=== Step 3/4: Network analysis — second run (RTT, zero-window, throughput) ==="
python3 network_thesis.py

echo ""
echo "=== Step 4/4: Network analysis — first vs. second run comparison ==="
python3 network_thesis_firstrun.py

echo ""
echo "All done. Figures: thesis_output/figures/  Tables: thesis_output/tables/"
