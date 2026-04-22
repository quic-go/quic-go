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

def save_fig(name):
    """Save current figure as both PNG and EPS."""
    plt.savefig(os.path.join(output_dir, f'{name}.png'), dpi=300, bbox_inches='tight', facecolor='white')
    plt.savefig(os.path.join(output_dir, f'{name}.eps'), format='eps', bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"Saved {name}.png + .eps")

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

# Helper: build stddev text box for a chart
def make_std_box(ax, std_entries, unit='ms'):
    """Add a text box in top-right corner with average σ per config."""
    lines = ['\u03c3 m\u00e9dio:']
    for name, avg_std in std_entries:
        lines.append(f'  {name}: {avg_std:.1f} {unit}')
    box_text = '\n'.join(lines)
    ax.text(0.98, 0.97, box_text, transform=ax.transAxes,
            fontsize=7, verticalalignment='top', horizontalalignment='right',
            fontfamily='monospace',
            bbox=dict(boxstyle='round,pad=0.4', facecolor='white', edgecolor='#cccccc'))

# Chart 1: Handshake vs Size
fig, ax = plt.subplots(figsize=(10, 6))
std_entries = []
classical_med = [safe_median(data_by_size, s, 'classical', 0, 'handshake') for s in sizes]
classical_std = [safe_std(data_by_size, s, 'classical', 0, 'handshake') for s in sizes]
ax.plot(x_pos, classical_med, 'o-', color=color_classical, linewidth=2, markersize=8, label='Cl\u00e1ssico')
std_entries.append(('Cl\u00e1ssico', np.mean(classical_std)))
for level in all_pqc:
    med = [safe_median(data_by_size, s, 'pqc', level, 'handshake') for s in sizes]
    std = [safe_std(data_by_size, s, 'pqc', level, 'handshake') for s in sizes]
    c = pqc_colors.get(level, '#999')
    ax.plot(x_pos, med, 'o-', color=c, linewidth=2, markersize=8, label=f'PQC-{level}')
    std_entries.append((f'PQC-{level}', np.mean(std)))
for level in all_hybrid:
    med = [safe_median(data_by_size, s, 'hybrid', level, 'handshake') for s in sizes]
    std = [safe_std(data_by_size, s, 'hybrid', level, 'handshake') for s in sizes]
    c = hybrid_colors.get(level, '#00aa44')
    ax.plot(x_pos, med, 's--', color=c, linewidth=2, markersize=8, label=f'H\u00edbrido-{level}')
    std_entries.append((f'H\u00edbrido-{level}', np.mean(std)))
ax.set_xlabel('Tamanho dos Dados', fontsize=12, fontweight='bold')
ax.set_ylabel('Dura\u00e7\u00e3o do Handshake (ms)', fontsize=12, fontweight='bold')
ax.set_title('Tempo de Handshake vs Tamanho dos Dados', fontsize=14, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(size_labels)
ax.legend(loc='upper left')
ax.grid(True, color='#cccccc', linewidth=0.5)
make_std_box(ax, std_entries, 'ms')
plt.tight_layout()
save_fig('scaling_handshake')

# Chart 2: Throughput vs Size
fig, ax = plt.subplots(figsize=(10, 6))
std_entries = []
classical_tp = [safe_median(data_by_size, s, 'classical', 0, 'throughput') for s in sizes]
classical_tp_std = [safe_std(data_by_size, s, 'classical', 0, 'throughput') for s in sizes]
max_tp = max(v for v in classical_tp if not np.isnan(v)) if classical_tp else 0
if max_tp < 10:
    tp_scale, tp_unit = 1000, 'Kbps'
else:
    tp_scale, tp_unit = 1, 'Mbps'
c_med = [v * tp_scale for v in classical_tp]
c_std_scaled = [v * tp_scale for v in classical_tp_std]
ax.plot(x_pos, c_med, 'o-', color=color_classical, linewidth=2, markersize=8, label='Cl\u00e1ssico')
std_entries.append(('Cl\u00e1ssico', np.mean(c_std_scaled)))
for level in all_pqc:
    med = [safe_median(data_by_size, s, 'pqc', level, 'throughput') * tp_scale for s in sizes]
    std = [safe_std(data_by_size, s, 'pqc', level, 'throughput') * tp_scale for s in sizes]
    c = pqc_colors.get(level, '#999')
    ax.plot(x_pos, med, 'o-', color=c, linewidth=2, markersize=8, label=f'PQC-{level}')
    std_entries.append((f'PQC-{level}', np.mean(std)))
for level in all_hybrid:
    med = [safe_median(data_by_size, s, 'hybrid', level, 'throughput') * tp_scale for s in sizes]
    std = [safe_std(data_by_size, s, 'hybrid', level, 'throughput') * tp_scale for s in sizes]
    c = hybrid_colors.get(level, '#00aa44')
    ax.plot(x_pos, med, 's--', color=c, linewidth=2, markersize=8, label=f'H\u00edbrido-{level}')
    std_entries.append((f'H\u00edbrido-{level}', np.mean(std)))
ax.set_xlabel('Tamanho dos Dados', fontsize=12, fontweight='bold')
ax.set_ylabel(f'Vaz\u00e3o ({tp_unit})', fontsize=12, fontweight='bold')
ax.set_title('Vaz\u00e3o vs Tamanho dos Dados', fontsize=14, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(size_labels)
ax.legend(loc='upper left')
ax.grid(True, color='#cccccc', linewidth=0.5)
make_std_box(ax, std_entries, tp_unit)
plt.tight_layout()
save_fig('scaling_throughput')

# Chart 3: Total Duration vs Size (log scale)
fig, ax = plt.subplots(figsize=(10, 6))
std_entries = []
c_med_td = [safe_median(data_by_size, s, 'classical', 0, 'total_duration') for s in sizes]
c_std_td = [safe_std(data_by_size, s, 'classical', 0, 'total_duration') for s in sizes]
ax.plot(x_pos, c_med_td, 'o-', color=color_classical, linewidth=2, markersize=8, label='Cl\u00e1ssico')
std_entries.append(('Cl\u00e1ssico', np.mean(c_std_td)))
for level in all_pqc:
    med = [safe_median(data_by_size, s, 'pqc', level, 'total_duration') for s in sizes]
    std = [safe_std(data_by_size, s, 'pqc', level, 'total_duration') for s in sizes]
    c = pqc_colors.get(level, '#999')
    ax.plot(x_pos, med, 'o-', color=c, linewidth=2, markersize=8, label=f'PQC-{level}')
    std_entries.append((f'PQC-{level}', np.mean(std)))
for level in all_hybrid:
    med = [safe_median(data_by_size, s, 'hybrid', level, 'total_duration') for s in sizes]
    std = [safe_std(data_by_size, s, 'hybrid', level, 'total_duration') for s in sizes]
    c = hybrid_colors.get(level, '#00aa44')
    ax.plot(x_pos, med, 's--', color=c, linewidth=2, markersize=8, label=f'H\u00edbrido-{level}')
    std_entries.append((f'H\u00edbrido-{level}', np.mean(std)))
ax.set_xlabel('Tamanho dos Dados', fontsize=12, fontweight='bold')
ax.set_ylabel('Dura\u00e7\u00e3o Total (ms)', fontsize=12, fontweight='bold')
ax.set_title('Dura\u00e7\u00e3o Ponta-a-Ponta vs Tamanho dos Dados', fontsize=14, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(size_labels)
ax.legend(loc='upper left')
ax.grid(True, color='#cccccc', linewidth=0.5)
make_std_box(ax, std_entries, 'ms')
plt.tight_layout()
save_fig('scaling_total_duration')

# Chart 4: Handshake as % of Total Time
fig, ax = plt.subplots(figsize=(10, 6))

def compute_pct_with_std(data, size, category, level):
    """Compute handshake % of total per-sample, return median and std of the ratio."""
    if category == 'classical':
        hs_vals = data[size]['classical']['handshake']
        td_vals = data[size]['classical']['total_duration']
    elif category == 'hybrid':
        hs_vals = data[size]['hybrid'].get(level, {}).get('handshake', [])
        td_vals = data[size]['hybrid'].get(level, {}).get('total_duration', [])
    else:
        hs_vals = data[size]['pqc'].get(level, {}).get('handshake', [])
        td_vals = data[size]['pqc'].get(level, {}).get('total_duration', [])
    ratios = [(h / t * 100) for h, t in zip(hs_vals, td_vals) if t > 0]
    ratios = [r for r in ratios if r > 0]
    if len(ratios) < 2:
        return np.median(ratios) if ratios else np.nan, 0.0
    return np.median(ratios), np.std(ratios)

std_entries = []
classical_pct = []
for s in sizes:
    m, sd = compute_pct_with_std(data_by_size, s, 'classical', 0)
    classical_pct.append(m)
ax.plot(x_pos, classical_pct, 'o-', color=color_classical, linewidth=2, markersize=8, label='Cl\u00e1ssico')
std_entries.append(('Cl\u00e1ssico', np.mean([compute_pct_with_std(data_by_size, s, 'classical', 0)[1] for s in sizes])))

for level in all_pqc:
    pct = []
    stds = []
    for s in sizes:
        m, sd = compute_pct_with_std(data_by_size, s, 'pqc', level)
        pct.append(m)
        stds.append(sd)
    c = pqc_colors.get(level, '#999')
    ax.plot(x_pos, pct, 'o-', color=c, linewidth=2, markersize=8, label=f'PQC-{level}')
    std_entries.append((f'PQC-{level}', np.mean(stds)))

for level in all_hybrid:
    pct = []
    stds = []
    for s in sizes:
        m, sd = compute_pct_with_std(data_by_size, s, 'hybrid', level)
        pct.append(m)
        stds.append(sd)
    c = hybrid_colors.get(level, '#00aa44')
    ax.plot(x_pos, pct, 's--', color=c, linewidth=2, markersize=8, label=f'H\u00edbrido-{level}')
    std_entries.append((f'H\u00edbrido-{level}', np.mean(stds)))

ax.set_xlabel('Tamanho dos Dados', fontsize=12, fontweight='bold')
ax.set_ylabel('Handshake como % do Tempo Total', fontsize=12, fontweight='bold')
ax.set_title('Sobrecarga do Handshake Diminui com Transfer\u00eancias Maiores', fontsize=14, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(size_labels)
ax.legend(loc='upper right', bbox_to_anchor=(0.75, 1.0))
ax.grid(True, color='#cccccc', linewidth=0.5)
make_std_box(ax, std_entries, '%')
plt.tight_layout()
save_fig('scaling_handshake_pct')

# Chart 5: Handshake Overhead vs Classical
fig, ax = plt.subplots(figsize=(10, 6))

def compute_overhead_with_std(data, size, category, level):
    """Compute per-sample overhead % vs classical median, return median and std."""
    c_vals = data[size]['classical']['handshake']
    c_median = np.median(remove_outliers(c_vals)) if c_vals else 0
    if c_median <= 0:
        return np.nan, 0.0
    if category == 'hybrid':
        vals = data[size]['hybrid'].get(level, {}).get('handshake', [])
    else:
        vals = data[size]['pqc'].get(level, {}).get('handshake', [])
    vals = remove_outliers(vals)
    overheads = [((v - c_median) / c_median * 100) for v in vals]
    if len(overheads) < 2:
        return np.median(overheads) if overheads else np.nan, 0.0
    return np.median(overheads), np.std(overheads)

std_entries = []
for level in all_pqc:
    overhead = []
    stds = []
    for s in sizes:
        m, sd = compute_overhead_with_std(data_by_size, s, 'pqc', level)
        overhead.append(m)
        stds.append(sd)
    c = pqc_colors.get(level, '#999')
    ax.plot(x_pos, overhead, 'o-', color=c, linewidth=2, markersize=8, label=f'PQC-{level}')
    std_entries.append((f'PQC-{level}', np.mean(stds)))

for level in all_hybrid:
    overhead = []
    stds = []
    for s in sizes:
        m, sd = compute_overhead_with_std(data_by_size, s, 'hybrid', level)
        overhead.append(m)
        stds.append(sd)
    c = hybrid_colors.get(level, '#00aa44')
    ax.plot(x_pos, overhead, 's--', color=c, linewidth=2, markersize=8, label=f'H\u00edbrido-{level}')
    std_entries.append((f'H\u00edbrido-{level}', np.mean(stds)))

ax.axhline(y=0, color='black', linestyle='--', linewidth=0.8)
ax.set_xlabel('Tamanho dos Dados', fontsize=12, fontweight='bold')
ax.set_ylabel('Sobrecarga do Handshake vs Clássico (%)', fontsize=12, fontweight='bold')
ax.set_title('Sobrecarga do Handshake por Tamanho dos Dados', fontsize=14, fontweight='bold')
ax.set_xticks(x_pos)
ax.set_xticklabels(size_labels)
ax.legend(loc='upper left')
ax.grid(True, color='#cccccc', linewidth=0.5)
make_std_box(ax, std_entries, '%')
plt.tight_layout()
save_fig('scaling_overhead')

# --- Grouped box plot distribution charts ---

def lighten(hex_color, factor=0.4):
    """Lighten a hex color by blending toward white (EPS-safe, no alpha)."""
    r, g, b = int(hex_color[1:3], 16), int(hex_color[3:5], 16), int(hex_color[5:7], 16)
    r = int(r + (255 - r) * factor)
    g = int(g + (255 - g) * factor)
    b = int(b + (255 - b) * factor)
    return f'#{r:02x}{g:02x}{b:02x}'

def get_raw_vals(data, size, category, level, metric):
    """Get raw values for a given config/size/metric."""
    if category == 'classical':
        return data[size]['classical'].get(metric, [])
    elif category == 'hybrid':
        return data[size]['hybrid'].get(level, {}).get(metric, [])
    else:
        return data[size]['pqc'].get(level, {}).get(metric, [])

# Build config list: (label, color, category, level)
configs_list = [('Clássico', color_classical, 'classical', 0)]
for level in all_pqc:
    configs_list.append((f'PQC-{level}', pqc_colors.get(level, '#999'), 'pqc', level))
for level in all_hybrid:
    configs_list.append((f'Híbrido-{level}', hybrid_colors.get(level, '#00aa44'), 'hybrid', level))

n_configs = len(configs_list)
width = 0.12

def make_grouped_boxplot(metric, ylabel, title, filename, scale_fn=None):
    """Generate a grouped box plot chart for a metric across data sizes."""
    fig, ax = plt.subplots(figsize=(12, 6))
    offsets = (np.arange(n_configs) - (n_configs - 1) / 2) * width
    legend_patches = []

    for i, (label, color, category, level) in enumerate(configs_list):
        positions = x_pos + offsets[i]
        box_data = []
        for s in sizes:
            vals = remove_outliers(get_raw_vals(data_by_size, s, category, level, metric))
            if scale_fn:
                vals = [scale_fn(v) for v in vals]
            box_data.append(vals if vals else [0])

        bp = ax.boxplot(box_data, positions=positions, widths=width * 0.85,
                        patch_artist=True, showfliers=False,
                        medianprops=dict(color='black', linewidth=1.5),
                        whiskerprops=dict(color=color, linewidth=1),
                        capprops=dict(color=color, linewidth=1))
        for patch in bp['boxes']:
            patch.set_facecolor(lighten(color))
            patch.set_edgecolor(color)
            patch.set_linewidth(1)

        legend_patches.append(plt.Rectangle((0, 0), 1, 1, fc=lighten(color), ec=color, label=label))

    ax.set_xlabel('Tamanho dos Dados', fontsize=12, fontweight='bold')
    ax.set_ylabel(ylabel, fontsize=12, fontweight='bold')
    ax.set_title(title, fontsize=14, fontweight='bold')
    ax.set_xticks(x_pos)
    ax.set_xticklabels(size_labels)
    ax.legend(handles=legend_patches, loc='best', fontsize=8)
    ax.grid(True, color='#cccccc', linewidth=0.5, axis='y')
    plt.tight_layout()
    save_fig(filename)

# Chart 6: Handshake Distribution (grouped box plot)
make_grouped_boxplot('handshake',
    'Duração do Handshake (ms)',
    'Distribuição do Handshake por Tamanho dos Dados',
    'scaling_handshake_dist')

# Chart 7: Throughput Distribution (grouped box plot)
tp_scale_fn = (lambda v: v * 1000) if max_tp < 10 else None
make_grouped_boxplot('throughput',
    f'Vazão ({tp_unit})',
    'Distribuição da Vazão por Tamanho dos Dados',
    'scaling_throughput_dist',
    scale_fn=tp_scale_fn)

# Chart 8: Total Duration Distribution (grouped box plot)
make_grouped_boxplot('total_duration',
    'Duração Total (ms)',
    'Distribuição da Duração Total por Tamanho dos Dados',
    'scaling_total_duration_dist')

print(f"\nAll scaling charts generated in {output_dir}/")
