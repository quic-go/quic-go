import os
import shutil

def move_test_files(root_dir='.', test_dir='tests'):
    for current_dir, dirs, files in os.walk(root_dir):
        # Ignorer le dossier "tests" lui-même
        if os.path.abspath(current_dir).startswith(os.path.abspath(test_dir)):
            continue

        for file in files:
            if file.endswith('_test.go'):
                # Chemin absolu du fichier actuel
                source_path = os.path.join(current_dir, file)

                # Calcul du chemin relatif depuis la racine
                relative_path = os.path.relpath(source_path, root_dir)

                # Nouveau chemin sous le dossier tests
                destination_path = os.path.join(test_dir, relative_path)

                # Créer le dossier destination s'il n'existe pas
                os.makedirs(os.path.dirname(destination_path), exist_ok=True)

                # Déplacer le fichier
                shutil.move(source_path, destination_path)
                print(f"Déplacé : {source_path} -> {destination_path}")

if __name__ == '__main__':
    move_test_files()
