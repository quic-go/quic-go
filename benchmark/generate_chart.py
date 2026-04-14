#!/usr/bin/env python3
"""Generate individual benchmark charts from CSV results."""

import csv
import matplotlib.pyplot as plt
import numpy as np
import sys
import os

input_file = sys.argv[1] if len(sys.argv) > 1 else 'test_results.csv'
output_dir = sys.argv[2] if len(sys.argv) > 2 else '.'

# Read CSV data
classical = {'handshake': [], 'throughput': [], 'cert_size': [], 'rtt': [], 'packets_sent': []}
configs = {}

with open(input_file, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row.get('error'):
            continue
        mode = row['mode']
        mlkem = int(row.get('mlkem_level', 0))
        mldsa = int(row.get('mldsa_level', 0))

        hs = float(row['handshake_duration_ms'])
        tp = float(row['throughput_mbps'])
        cert = int(row.get('cert_chain_size_bytes', 0))
        rtt = float(row.get('rtt_smoothed_ms', 0))
        pkt = int(row.get('packets_sent', 0))

        if mode == 'classical':
            classical['handshake'].append(hs)
            classical['throughput'].append(tp)
            classical['cert_size'].append(cert)
            classical['rtt'].append(rtt)
            classical['packets_sent'].append(pkt)
        else:
            if mode == 'hybrid':
                label = f'Híbrido-{mldsa}'
            else:
                label = f'KEM-{mlkem}'
            if label not in configs:
                configs[label] = {'handshake': [], 'throughput': [], 'cert_size': [], 'rtt': [], 'packets_sent': []}
            configs[label]['handshake'].append(hs)
            configs[label]['throughput'].append(tp)
            configs[label]['cert_size'].append(cert)
            configs[label]['rtt'].append(rtt)
            configs[label]['packets_sent'].append(pkt)

labels = ['Clássico'] + list(configs.keys())
color_map = {
    'Clássico': '#0060ad',
    'KEM-512': '#dd181f', 'KEM-768': '#ff6b6b', 'KEM-1024': '#c44569',
    'Híbrido-65': '#00aa44', 'Híbrido-87': '#006622',
}

def get_color(label):
    return color_map.get(label, '#999999')

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

def med(vals):
    vals = remove_outliers(vals)
    return np.median(vals) if vals else 0

# Chart 1: Handshake Duration
fig, ax = plt.subplots(figsize=(10, 6))
values = [med(classical['handshake'])] + [med(configs[k]['handshake']) for k in configs]
colors = [get_color(l) for l in labels]
bars = ax.bar(range(len(labels)), values, color=colors, edgecolor='black', linewidth=1.2)
for bar in bars:
    h = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., h, f'{h:.2f}', ha='center', va='bottom', fontweight='bold')
ax.set_ylabel('Duração do Handshake (ms)', fontsize=12, fontweight='bold')
ax.set_title('Desempenho do Handshake por Modo Criptográfico', fontsize=14, fontweight='bold')
ax.set_xticks(range(len(labels)))
ax.set_xticklabels(labels, rotation=20, ha='right', fontsize=10)
ax.grid(True, alpha=0.3, axis='y')
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'chart_handshake.png'), dpi=300, bbox_inches='tight', facecolor='white')
plt.close()
print(f"Saved chart_handshake.png")

# Chart 2: Throughput (auto-detect Kbps vs Mbps)
fig, ax = plt.subplots(figsize=(10, 6))
values_mbps = [med(classical['throughput'])] + [med(configs[k]['throughput']) for k in configs]
max_tp = max(values_mbps) if values_mbps else 0
if max_tp < 10:
    # Use Kbps for small transfers
    values = [v * 1000 for v in values_mbps]
    tp_unit = 'Kbps'
    fmt = '{h:.1f}'
else:
    values = values_mbps
    tp_unit = 'Mbps'
    fmt = '{h:.0f}'
bars = ax.bar(range(len(labels)), values, color=colors, edgecolor='black', linewidth=1.2)
for bar in bars:
    h = bar.get_height()
    label_text = f'{h:.1f}' if tp_unit == 'Kbps' else f'{h:.0f}'
    ax.text(bar.get_x() + bar.get_width()/2., h, label_text, ha='center', va='bottom', fontweight='bold')
ax.set_ylabel(f'Vazão ({tp_unit})', fontsize=12, fontweight='bold')
ax.set_title('Desempenho de Transferência de Dados', fontsize=14, fontweight='bold')
ax.set_xticks(range(len(labels)))
ax.set_xticklabels(labels, rotation=20, ha='right', fontsize=10)
ax.grid(True, alpha=0.3, axis='y')
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'chart_throughput.png'), dpi=300, bbox_inches='tight', facecolor='white')
plt.close()
print(f"Saved chart_throughput.png (unit: {tp_unit})")

# Chart 3: Certificate Size
fig, ax = plt.subplots(figsize=(10, 6))
values = [med(classical['cert_size'])/1024] + [med(configs[k]['cert_size'])/1024 for k in configs]
bars = ax.bar(range(len(labels)), values, color=colors, edgecolor='black', linewidth=1.2)
for bar in bars:
    h = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2., h, f'{h:.1f}', ha='center', va='bottom', fontweight='bold')
ax.set_ylabel('Tamanho da Cadeia de Certificados (KB)', fontsize=12, fontweight='bold')
ax.set_title('Sobrecarga no Tamanho do Certificado', fontsize=14, fontweight='bold')
ax.set_xticks(range(len(labels)))
ax.set_xticklabels(labels, rotation=20, ha='right', fontsize=10)
ax.grid(True, alpha=0.3, axis='y')
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'chart_cert_size.png'), dpi=300, bbox_inches='tight', facecolor='white')
plt.close()
print(f"Saved chart_cert_size.png")

# Chart 4: Handshake Distribution (box plot) - outliers removed for clarity
fig, ax = plt.subplots(figsize=(10, 6))
box_data = [remove_outliers(classical['handshake'])] + [remove_outliers(configs[k]['handshake']) for k in configs]
box_colors = [get_color(l) for l in labels]

bp = ax.boxplot(box_data, labels=labels, patch_artist=True, widths=0.6,
                showfliers=False,
                medianprops=dict(color='black', linewidth=2),
                whiskerprops=dict(linewidth=1.5),
                capprops=dict(linewidth=1.5))
for patch, color in zip(bp['boxes'], box_colors):
    patch.set_facecolor(color)
    patch.set_alpha(0.7)

# Add median and stddev labels above the top whisker cap
whisker_tops = [cap.get_ydata()[0] for cap in bp['caps'][1::2]]
for i, data in enumerate(box_data):
    median_val = np.median(data)
    std_val = np.std(data)
    top = whisker_tops[i]
    ax.text(i + 1, top, f'\n{median_val:.1f} ms\n\u00b1{std_val:.1f} ms',
            va='bottom', ha='center', fontsize=9, fontweight='bold', color=box_colors[i])

ax.set_ylabel('Duração do Handshake (ms)', fontsize=12, fontweight='bold')
ax.set_title('Distribuição da Duração do Handshake', fontsize=14, fontweight='bold')
ax.tick_params(axis='x', rotation=20)
ax.grid(True, alpha=0.3, axis='y')
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'chart_handshake_dist.png'), dpi=300, bbox_inches='tight', facecolor='white')
plt.close()
print(f"Saved chart_handshake_dist.png")

print("All charts generated.")
