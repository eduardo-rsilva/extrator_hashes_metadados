import subprocess
import shutil
import os
import sys
import hashlib

# ===== ANTES DE COMPILAR O EXECUTÁVEL =====
# 1) descompactar exiftool-13.51_64.zip dentro de src/

# 2) renomear o arquivo exiftool-13.51_64/exiftool(-k).exe como exiftool-13.51_64/exiftool.exe

# 3) rodar no terminal: python build.py

# ===== GERAÇÃO DO HASH DO CÓDIGO FONTE =====
source_file = os.path.join("src", "extrator_hashes_metadados.py")
with open(source_file, "rb") as f:
    source_hash = hashlib.sha256(f.read()).hexdigest().upper()

hash_module = os.path.join("src", "hash_fonte.py")
with open(hash_module, "w", encoding="utf-8") as f:
    f.write('# Arquivo gerado automaticamente durante a compilação.\n')
    f.write(f'HASH_DO_CODIGO_FONTE = "{source_hash}"\n')

print(f"Hash do código fonte: {source_hash}")
print(f"Arquivo {hash_module} gerado.")

# ===== COMPILAÇÃO COM NUITKA =====
nuitka_command = [
    sys.executable, "-m", "nuitka",
    "--output-dir=src",
    "--standalone",
    "--windows-console-mode=disable",
    "--enable-plugin=pyside6",
    "--enable-plugin=anti-bloat",
    "--windows-icon-from-ico=src/app.ico",
    "--include-data-files=src/app.ico=app.ico",
    "--include-data-files=src/extrator_hashes_metadados.py=extrator_hashes_metadados.py",
    # Inclui também o arquivo com o hash para auditoria
    "--include-data-files=src/hash_fonte.py=hash_fonte.py",
    "--include-package=PIL",
    "--include-package=cv2",
    "--include-package=pypdf",
    "--include-package=olefile",
    "--include-package=LnkParse3",
    "--include-package=yaml",
    "--include-package=pefile",
    "--include-package=extract_msg",
    "--include-package=tinytag",
    "--include-package=cryptography",
    "src/extrator_hashes_metadados.py"
]

print("Iniciando compilação com Nuitka...")
subprocess.run(nuitka_command, check=True)
print("Compilação concluída!")

# ===== CÓPIA DA PASTA DO EXIFTOOL =====
origem_exiftool = "src/exiftool-13.51_64"
destino_exiftool = os.path.join("src", "extrator_hashes_metadados.dist", "exiftool-13.51_64")

print(f"Copiando {origem_exiftool} para {destino_exiftool}...")
if os.path.exists(destino_exiftool):
    shutil.rmtree(destino_exiftool)
shutil.copytree(origem_exiftool, destino_exiftool)

print("Build finalizado com sucesso! A pasta 'extrator_hashes_metadados.dist' está pronta.")

print("Gerando registro de integridade da pasta .dist (Hashes)...")

dist_dir = os.path.join("src", "extrator_hashes_metadados.dist")
manifesto_path = os.path.join("src", "hashes_lancamento.sha256")

with open(manifesto_path, "w", encoding="utf-8") as f_out:
    # Adiciona primeiro os metadados principais
    f_out.write(f"# Hash do Codigo Fonte (.py): {source_hash}\n")
    f_out.write(f"# Gerado apos compilacao Nuitka (Standalone)\n\n")

    # Percorre todos os arquivos da pasta .dist (incluindo o seu .exe e .dlls)
    for root, dirs, files in os.walk(dist_dir):
        for file in files:
            filepath = os.path.join(root, file)
            # Lê cada arquivo e gera o hash
            with open(filepath, "rb") as f_in:
                file_hash = hashlib.sha256(f_in.read()).hexdigest().upper()

            # Formato padrão de lista de hashes (facilmente verificável por softwares)
            # Salva o caminho relativo para ficar limpo
            rel_path = os.path.relpath(filepath, "src")
            f_out.write(f"{file_hash} *{rel_path}\n")

print(f"Manifesto de integridade gerado em: {manifesto_path}")
print("Forneça este arquivo junto com a pasta .dist para auditoria.")
