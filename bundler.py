import json
import fnmatch
import os

# === Chargement de la configuration ===
with open("bundler_config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

root_dir = config.get("source_root", ".")
output_file = config.get("output_file", "bundle_output.txt")
ignore_file_path = config.get("ignore_file", ".bundleignore")
allowed_extensions = config.get("include_extensions", [])

# === Chargement des patterns d'exclusion ===

def load_ignore_patterns(ignore_file):
    if not os.path.exists(ignore_file):
        return []
    with open(ignore_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]

ignore_patterns = load_ignore_patterns(ignore_file_path)

def should_ignore(path):
    for pattern in ignore_patterns:
        if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(os.path.basename(path), pattern):
            return True
    return False

def has_allowed_extension(filename):
    return any(filename.endswith(ext) for ext in allowed_extensions)

# === Bundle des fichiers texte correspondant ===

with open(output_file, "w", encoding="utf-8") as bundle:
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Filtrer les répertoires ignorés
        dirnames[:] = [d for d in dirnames if not should_ignore(os.path.join(dirpath, d))]
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(filepath, root_dir)

            if should_ignore(filepath) or not has_allowed_extension(filename):
                continue

            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    bundle.write(f"# ===== FILE: {rel_path} =====\n")
                    bundle.write(f.read())
                    bundle.write("\n\n")
            except Exception as e:
                print(f"Skipped {filepath}: {e}")

output_file
