#!/usr/bin/env python3
"""Generate comprehensive benchmark table from CSV results."""

import csv
import matplotlib.pyplot as plt
import numpy as np
import sys

# Get input file from command line or use default
input_file = sys.argv[1] if len(sys.argv) > 1 else 'test_results.csv'
output_file = sys.argv[2] if len(sys.argv) > 2 else 'benchmark_table.png'

# Read CSV data
classical = {
    'handshake': [], 'throughput': [], 'rtt': [],
    'packets_sent': [], 'cert_size': [], 'ttfb': [], 'handshake_bytes': []
}
configs = {}  # keyed by short label

with open(input_file, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row.get('error'):
            continue

        mode = row['mode']
        mlkem = int(row.get('mlkem_level', 0))
        mldsa = int(row.get('mldsa_level', 0))

        metrics = {
            'handshake': float(row['handshake_duration_ms']),
            'throughput': float(row['throughput_mbps']),
            'rtt': float(row.get('rtt_smoothed_ms', 0)),
            'packets_sent': int(row.get('packets_sent', 0)),
            'cert_size': int(row.get('cert_chain_size_bytes', 0)),
            'ttfb': float(row.get('time_to_first_byte_ms', 0)),
            'handshake_bytes': int(row.get('handshake_bytes_sent', 0)),
        }

        if mode == 'classical':
            for k, v in metrics.items():
                classical[k].append(v)
        else:
            if mode == 'hybrid':
                label = f'Híbrido\n(DSA-{mldsa})'
            else:
                label = f'PQC\n(KEM-{mlkem})'

            if label not in configs:
                configs[label] = {k: [] for k in metrics}
            for k, v in metrics.items():
                configs[label][k].append(v)

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

def mn(vals):
    vals = [v for v in vals if v > 0]
    return np.min(vals) if vals else 0

def mx(vals):
    vals = [v for v in vals if v > 0]
    return np.max(vals) if vals else 0

def std(vals):
    vals = remove_outliers(vals)
    return np.std(vals) if len(vals) >= 2 else 0

# Build table
cols = ['Clássico'] + list(configs.keys())
num_cols = len(cols) + 1  # +1 for Metric column

rows = []
rows.append(['', *cols])
rows.append([''] * (num_cols))
rows.append(['Handshake (ms)'] + [''] * len(cols))

c_hs = med(classical['handshake'])
rows.append(['  Mediana', f'{c_hs:.2f}'] + [f"{med(configs[k]['handshake']):.2f}" for k in configs])
rows.append(['  Min', f'{mn(classical["handshake"]):.2f}'] + [f"{mn(configs[k]['handshake']):.2f}" for k in configs])
rows.append(['  Max', f'{mx(classical["handshake"]):.2f}'] + [f"{mx(configs[k]['handshake']):.2f}" for k in configs])
rows.append(['  Desv. Padrão', f'{std(classical["handshake"]):.2f}'] + [f"{std(configs[k]['handshake']):.2f}" for k in configs])

rows.append([''] * (num_cols))
rows.append(['Vazão (Mbps)'] + [''] * len(cols))
rows.append(['  Mediana', f'{med(classical["throughput"]):.1f}'] + [f"{med(configs[k]['throughput']):.1f}" for k in configs])

rows.append([''] * (num_cols))
rows.append(['Cadeia de Certificados (KB)'] + [''] * len(cols))
c_cert = med(classical['cert_size'])
rows.append(['  Tamanho', f'{c_cert/1024:.1f}'] + [f"{med(configs[k]['cert_size'])/1024:.1f}" for k in configs])

rows.append([''] * (num_cols))
rows.append(['Métricas QUIC'] + [''] * len(cols))
rows.append(['  Pacotes Enviados', f"{med(classical['packets_sent']):.0f}"] + [f"{med(configs[k]['packets_sent']):.0f}" for k in configs])
rows.append(['  Bytes do HS', f"{med(classical['handshake_bytes'])/1024:.1f} KB"] + [f"{med(configs[k]['handshake_bytes'])/1024:.1f} KB" for k in configs])
rows.append(['  RTT', f"{med(classical['rtt']):.2f} ms"] + [f"{med(configs[k]['rtt']):.2f} ms" for k in configs])

rows.append([''] * (num_cols))
rows.append(['Sobrecarga vs Clássico'] + [''] * len(cols))
hs_overhead = ['  Handshake', '---']
for k in configs:
    pct = ((med(configs[k]['handshake']) - c_hs) / c_hs * 100) if c_hs > 0 else 0
    hs_overhead.append(f'{pct:+.1f}%')
rows.append(hs_overhead)

cert_overhead = ['  Certificado', '---']
for k in configs:
    pct = ((med(configs[k]['cert_size']) - c_cert) / c_cert * 100) if c_cert > 0 else 0
    cert_overhead.append(f'{pct:+.0f}%')
rows.append(cert_overhead)

# Determine iterations for title
iters = len(classical['handshake'])

# Create figure - wider for more columns
fig_width = max(14, 3 * num_cols)
fig, ax = plt.subplots(figsize=(fig_width, 10))
ax.axis('off')

title = f'Benchmark QUIC PQC - Comparação de Desempenho ({iters} iterações)'
fig.suptitle(title, fontsize=16, fontweight='bold', y=0.97)

# Equal-width columns
col_widths = [1.0 / num_cols] * num_cols

table = ax.table(cellText=rows, cellLoc='center', loc='center', colWidths=col_widths)
table.auto_set_font_size(False)
table.set_fontsize(9)
table.scale(1, 2.0)

# Style header
for i in range(num_cols):
    cell = table[(0, i)]
    cell.set_facecolor('#0060ad')
    cell.set_text_props(weight='bold', color='white', fontsize=10)

# Style section headers (rows where col 1+ are empty but col 0 has text without indent)
for idx, row in enumerate(rows):
    if row[0] and not row[0].startswith('  ') and row[0] != '' and idx > 0:
        if all(c == '' for c in row[1:]):
            for col in range(num_cols):
                table[(idx, col)].set_facecolor('#e8f4f8')
                table[(idx, col)].set_text_props(weight='bold', fontsize=9)

# Style separator rows
for idx, row in enumerate(rows):
    if all(c == '' for c in row):
        for col in range(num_cols):
            table[(idx, col)].set_facecolor('#f5f5f5')
            table[(idx, col)].set_height(0.02)

# Highlight overhead values
for idx, row in enumerate(rows):
    for col_idx, cell_val in enumerate(row):
        if isinstance(cell_val, str) and cell_val.startswith('+'):
            table[(idx, col_idx)].set_text_props(weight='bold', color='#dd181f', fontsize=9)
        elif isinstance(cell_val, str) and cell_val.startswith('-') and '%' in cell_val:
            table[(idx, col_idx)].set_text_props(weight='bold', color='#00aa00', fontsize=9)

for key, cell in table.get_celld().items():
    cell.set_edgecolor('#cccccc')
    cell.set_linewidth(0.8)

plt.tight_layout(rect=[0, 0.02, 1, 0.94])
plt.savefig(output_file, dpi=300, bbox_inches='tight', facecolor='white')
print(f"Table saved as {output_file}")
