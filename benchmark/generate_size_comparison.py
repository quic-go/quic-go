#!/usr/bin/env python3
"""Generate individual size-scaling comparison charts from multiple benchmark results."""

import csv
import matplotlib.pyplot as plt
import numpy as np
import sys
import glob
import re
import os

def parse_size_from_filename(filename):
    """Parse size from filename, returning size in KB for unified sorting."""
    match_kb = re.search(r'_(\d+)kb\.csv', filename.lower())
    match_mb = re.search(r'_(\d+)mb\.csv', filename.lower())
    if match_kb:
        return int(match_kb.group(1))  # already in KB
    if match_mb:
        return int(match_mb.group(1)) * 1024  # convert MB to KB
    return None

def format_size(size_kb):
    """Format size in KB to human-readable string."""
    if size_kb >= 1024 * 1000:
        return f"{size_kb / (1024 * 1000):.0f}GB"
    if size_kb >= 1024:
        return f"{size_kb // 1024}MB"
    return f"{size_kb}KB"

# Find CSV files
if len(sys.argv) > 1:
    csv_files = glob.glob(sys.argv[1])
else:
    csv_files = glob.glob('comprehensive_results_*kb.csv') + glob.glob('comprehensive_results_*mb.csv')

if not csv_files:
    print("No CSV files found")
    sys.exit(1)

output_dir = sys.argv[2] if len(sys.argv) > 2 else '.'

print(f"Found {len(csv_files)} result files")

# Parse data
data_by_size = {}
for csv_file in sorted(csv_files):
    size_mb = parse_size_from_filename(csv_file)
    if size_mb is None:
        continue

    print(f"  Reading {csv_file} ({format_size(size_mb)})...")
    data_by_size[size_mb] = {'classical': {'handshake': [], 'throughput': [], 'total_duration': []}, 'pqc': {}, 'hybrid': {}}

    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('error'):
                continue
            mode = row['mode']
            mlkem = int(row.get('mlkem_level', 0))
            hs = float(row['handshake_duration_ms'])
            tp = float(row['throughput_mbps'])
            td = float(row['total_duration_ms'])

            if mode == 'classical':
                data_by_size[size_mb]['classical']['handshake'].append(hs)
                data_by_size[size_mb]['classical']['throughput'].append(tp)
                data_by_size[size_mb]['classical']['total_duration'].append(td)
            elif mode == 'hybrid':
                if mlkem not in data_by_size[size_mb]['hybrid']:
                    data_by_size[size_mb]['hybrid'][mlkem] = {'handshake': [], 'throughput': [], 'total_duration': []}
                data_by_size[size_mb]['hybrid'][mlkem]['handshake'].append(hs)
                data_by_size[size_mb]['hybrid'][mlkem]['throughput'].append(tp)
                data_by_size[size_mb]['hybrid'][mlkem]['total_duration'].append(td)
            else:
                if mlkem not in data_by_size[size_mb]['pqc']:
                    data_by_size[size_mb]['pqc'][mlkem] = {'handshake': [], 'throughput': [], 'total_duration': []}
                data_by_size[size_mb]['pqc'][mlkem]['handshake'].append(hs)
                data_by_size[size_mb]['pqc'][mlkem]['throughput'].append(tp)
                data_by_size[size_mb]['pqc'][mlkem]['total_duration'].append(td)

if not data_by_size:
    print("No valid data")
    sys.exit(1)

sizes = sorted(data_by_size.keys())
size_labels = [format_size(s) for s in sizes]
x_pos = np.arange(len(sizes))

all_pqc = sorted(set(l for d in data_by_size.values() for l in d['pqc']))
all_hybrid = sorted(set(l for d in data_by_size.values() for l in d['hybrid']))

color_classical = '#0060ad'
pqc_colors = {512: '#dd181f', 768: '#ff6b6b', 1024: '#c44569'}
hybrid_colors = {768: '#00aa44', 1024: '#006622'}

def remove_outliers(vals):
    """Remove values beyond 2x IQR from Q1/Q3."""
    vals = [v for v in vals if v > 0]
    if len(vals) < 4:
        return vals
    q1, q3 = np.percentile(vals, [25, 75])
    iqr = q3 - q1
    lower = q1 - 2 * iqr
    upper = q3 + 2 * iqr
    return [v for v in vals if lower <= v <= upper]

def safe_median(data, size, category, level, metric):
    if category == 'classical':
        vals = data[size]['classical'][metric]
    elif category == 'hybrid':
        vals = data[size]['hybrid'].get(level, {}).get(metric, [])
    else:
        vals = data[size]['pqc'].get(level, {}).get(metric, [])
    vals = remove_outliers(vals)
    return np.median(vals) if vals else np.nan

def safe_std(data, size, category, level, metric):
    if category == 'classical':
        vals = data[size]['classical'][metric]
    elif category == 'hybrid':
        vals = data[size]['hybrid'].get(level, {}).get(metric, [])
    else:
        vals = data[size]['pqc'].get(level, {}).get(metric, [])
    vals = remove_outliers(vals)
    return np.std(vals) if len(vals) >= 2 else 0.0

# Chart 1: Handshake vs Size (with ±1 stddev shaded bands)
fig, ax = plt.subplots(figsize=(10, 6))
classical_med = [safe_median(data_by_size, s, 'classical', 0, 'handshake') for s in sizes]
classical_std = [safe_std(data_by_size, s, 'classical', 0, 'handshake') for s in sizes]
ax.plot(x_pos, classical_med, 'o-', color=color_classical, linewidth=2, markersize=8, label='Clássico')
ax.fill_between(x_pos, [m - d for m, d in zip(classical_med, classical_std)],
                [m + d for m, d in zip(classical_med, classical_std)], color=color_classical, alpha=0.15)
for level in all_pqc:
    med = [safe_median(data_by_size, s, 'pqc', level, 'handshake') for s in sizes]
    std = [safe_std(data_by_size, s, 'pqc', level, 'handshake') for s in sizes]
    c = pqc_colors.get(level, '#999')
    ax.plot(x_pos, med, 'o-', color=c, linewidth=2, markersize=8, label=f'PQC-{level}')
    ax.fill_between(x_pos, [m - d for m, d in zip(med, std)], [m + d for m, d in zip(med, std)], color=c, alpha=0.15)
for level in all_hybrid:
    med = [safe_median(data_by_size, s, 'hybrid', level, 'handshake') for s in sizes]
    std = [safe_std(data_by_size, s, 'hybrid', level, 'handshake') for s in sizes]
    c = hybrid_colors.get(level, '#00aa44')
    ax.plot(x_pos, med, 's--', color=c, linewidth=2, markersize=8, label=f'Híbrido-{level}')
    ax.fill_between(x_pos, [m - d for m, d in zip(med, std)], [m + d for m, d in zip(med, std)], color=c, alpha=0.15)
ax.set_xlabel('Tamanho dos Dados', fontsize=12, fontweight='bold')
ax.set_ylabel('Duração do Handshake (ms)', fontsize=12, fontweight='bold')
ax.set_title('Tempo de Handshake vs Tamanho dos Dados', fontsize=14, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(size_labels)
ax.legend(loc='best')
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'scaling_handshake.png'), dpi=300, bbox_inches='tight', facecolor='white')
plt.close()
print("Saved scaling_handshake.png")

# Chart 2: Throughput vs Size (auto-detect Kbps vs Mbps)
fig, ax = plt.subplots(figsize=(10, 6))
classical_tp = [safe_median(data_by_size, s, 'classical', 0, 'throughput') for s in sizes]
max_tp = max(v for v in classical_tp if not np.isnan(v)) if classical_tp else 0
if max_tp < 10:
    tp_scale, tp_unit = 1000, 'Kbps'
else:
    tp_scale, tp_unit = 1, 'Mbps'
ax.plot(x_pos, [v * tp_scale for v in classical_tp],
        'o-', color=color_classical, linewidth=2, markersize=8, label='Clássico')
for level in all_pqc:
    vals = [safe_median(data_by_size, s, 'pqc', level, 'throughput') * tp_scale for s in sizes]
    ax.plot(x_pos, vals,
            'o-', color=pqc_colors.get(level, '#999'), linewidth=2, markersize=8, label=f'PQC-{level}')
for level in all_hybrid:
    vals = [safe_median(data_by_size, s, 'hybrid', level, 'throughput') * tp_scale for s in sizes]
    ax.plot(x_pos, vals,
            's--', color=hybrid_colors.get(level, '#00aa44'), linewidth=2, markersize=8, label=f'Híbrido-{level}')
ax.set_xlabel('Tamanho dos Dados', fontsize=12, fontweight='bold')
ax.set_ylabel(f'Vazão ({tp_unit})', fontsize=12, fontweight='bold')
ax.set_title('Vazão vs Tamanho dos Dados', fontsize=14, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(size_labels)
ax.legend(loc='best')
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'scaling_throughput.png'), dpi=300, bbox_inches='tight', facecolor='white')
plt.close()
print(f"Saved scaling_throughput.png (unit: {tp_unit})")

# Chart 3: Total Duration vs Size (log scale)
fig, ax = plt.subplots(figsize=(10, 6))
ax.plot(x_pos, [safe_median(data_by_size, s, 'classical', 0, 'total_duration') for s in sizes],
        'o-', color=color_classical, linewidth=2, markersize=8, label='Clássico')
for level in all_pqc:
    ax.plot(x_pos, [safe_median(data_by_size, s, 'pqc', level, 'total_duration') for s in sizes],
            'o-', color=pqc_colors.get(level, '#999'), linewidth=2, markersize=8, label=f'PQC-{level}')
for level in all_hybrid:
    ax.plot(x_pos, [safe_median(data_by_size, s, 'hybrid', level, 'total_duration') for s in sizes],
            's--', color=hybrid_colors.get(level, '#00aa44'), linewidth=2, markersize=8, label=f'Híbrido-{level}')
ax.set_xlabel('Tamanho dos Dados', fontsize=12, fontweight='bold')
ax.set_ylabel('Duração Total (ms)', fontsize=12, fontweight='bold')
ax.set_title('Duração Ponta-a-Ponta vs Tamanho dos Dados', fontsize=14, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(size_labels)
ax.set_yscale('log')
ax.legend(loc='best')
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'scaling_total_duration.png'), dpi=300, bbox_inches='tight', facecolor='white')
plt.close()
print("Saved scaling_total_duration.png")

# Chart 4: Handshake as % of Total Time
fig, ax = plt.subplots(figsize=(10, 6))
classical_pct = []
for s in sizes:
    hs = safe_median(data_by_size, s, 'classical', 0, 'handshake')
    tot = safe_median(data_by_size, s, 'classical', 0, 'total_duration')
    classical_pct.append((hs / tot * 100) if tot > 0 else np.nan)
ax.plot(x_pos, classical_pct, 'o-', color=color_classical, linewidth=2, markersize=8, label='Clássico')

for level in all_pqc:
    pct = []
    for s in sizes:
        hs = safe_median(data_by_size, s, 'pqc', level, 'handshake')
        tot = safe_median(data_by_size, s, 'pqc', level, 'total_duration')
        pct.append((hs / tot * 100) if tot > 0 else np.nan)
    ax.plot(x_pos, pct, 'o-', color=pqc_colors.get(level, '#999'), linewidth=2, markersize=8, label=f'PQC-{level}')

for level in all_hybrid:
    pct = []
    for s in sizes:
        hs = safe_median(data_by_size, s, 'hybrid', level, 'handshake')
        tot = safe_median(data_by_size, s, 'hybrid', level, 'total_duration')
        pct.append((hs / tot * 100) if tot > 0 else np.nan)
    ax.plot(x_pos, pct, 's--', color=hybrid_colors.get(level, '#00aa44'), linewidth=2, markersize=8, label=f'Híbrido-{level}')

ax.set_xlabel('Tamanho dos Dados', fontsize=12, fontweight='bold')
ax.set_ylabel('Handshake como % do Tempo Total', fontsize=12, fontweight='bold')
ax.set_title('Sobrecarga do Handshake Diminui com Transferências Maiores', fontsize=14, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(size_labels)
ax.legend(loc='best')
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'scaling_handshake_pct.png'), dpi=300, bbox_inches='tight', facecolor='white')
plt.close()
print("Saved scaling_handshake_pct.png")

# Chart 5: Handshake Overhead vs Classical
fig, ax = plt.subplots(figsize=(10, 6))
for level in all_pqc:
    overhead = []
    for s in sizes:
        pqc_hs = safe_median(data_by_size, s, 'pqc', level, 'handshake')
        c_hs = safe_median(data_by_size, s, 'classical', 0, 'handshake')
        overhead.append(((pqc_hs - c_hs) / c_hs * 100) if c_hs > 0 else np.nan)
    ax.plot(x_pos, overhead, 'o-', color=pqc_colors.get(level, '#999'), linewidth=2, markersize=8, label=f'PQC-{level}')

for level in all_hybrid:
    overhead = []
    for s in sizes:
        h_hs = safe_median(data_by_size, s, 'hybrid', level, 'handshake')
        c_hs = safe_median(data_by_size, s, 'classical', 0, 'handshake')
        overhead.append(((h_hs - c_hs) / c_hs * 100) if c_hs > 0 else np.nan)
    ax.plot(x_pos, overhead, 's--', color=hybrid_colors.get(level, '#00aa44'), linewidth=2, markersize=8, label=f'Híbrido-{level}')

ax.axhline(y=0, color='black', linestyle='--', linewidth=1, alpha=0.5)
ax.set_xlabel('Tamanho dos Dados', fontsize=12, fontweight='bold')
ax.set_ylabel('Sobrecarga do Handshake vs Clássico (%)', fontsize=12, fontweight='bold')
ax.set_title('Sobrecarga do Handshake por Tamanho dos Dados', fontsize=14, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(size_labels)
ax.legend(loc='best')
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'scaling_overhead.png'), dpi=300, bbox_inches='tight', facecolor='white')
plt.close()
print("Saved scaling_overhead.png")

print(f"\nAll scaling charts generated in {output_dir}/")
