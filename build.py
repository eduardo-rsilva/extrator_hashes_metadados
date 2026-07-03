import subprocess
import shutil
import os
import sys
import hashlib

from src.extrator_hashes_metadados import VERSAO_APP

# ===== ANTES DE COMPILAR O EXECUTÁVEL =====
# 1) descompactar exiftool-13.59_64.zip dentro de src/

# 2) renomear o arquivo exiftool-13.59_64/exiftool(-k).exe como exiftool-13.59_64/exiftool.exe

# 3) rodar no terminal: compilar.bat

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
    # --- NOVAS FLAGS: COMPILADOR E METADADOS ANTI-FALSO POSITIVO ---
    "--msvc=latest",
    "--windows-company-name=ERS-IC/SP-NIC",
    "--windows-product-name=Extrator de Hashes e Metadados",
    "--windows-file-description=Ferramenta Forense de Extracao de Metadados",
    f"--windows-product-version={VERSAO_APP}.0",
    f"--windows-file-version={VERSAO_APP}.0",
    # ---------------------------------------------------------------
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
origem_exiftool = "src/exiftool-13.59_64"
destino_exiftool = os.path.join("src", "extrator_hashes_metadados.dist", "exiftool-13.59_64")

print(f"Copiando {origem_exiftool} para {destino_exiftool}...")
if os.path.exists(destino_exiftool):
    shutil.rmtree(destino_exiftool)
shutil.copytree(origem_exiftool, destino_exiftool)

# ===== CÓPIA DA PASTA DO EWF =====
origem_ewf = "src/ewf"
destino_ewf = os.path.join("src", "extrator_hashes_metadados.dist", "ewf")

print(f"Copiando {origem_ewf} para {destino_ewf}...")
if os.path.exists(destino_ewf):
    shutil.rmtree(destino_ewf)
shutil.copytree(origem_ewf, destino_ewf)

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

# ===== EMPACOTAMENTO FINAL (ZIP) =====
print("\nEmpacotando arquivos de lançamento (ZIP)...")

# Cria o diretório 'exe' se não existir (no mesmo nível de 'src')
exe_dir = "exe"
os.makedirs(exe_dir, exist_ok=True)

# Define o nome e o caminho do arquivo .zip (sem a extensão, pois o shutil.make_archive adiciona)
nome_zip_base = f"Extrator_ERS-IC-SP-NIC_v{VERSAO_APP}"
caminho_zip_base = os.path.join(exe_dir, nome_zip_base)

# Copia o manifesto para dentro da pasta .dist temporariamente para que ele fique na raiz do ZIP
manifesto_temp_path = os.path.join(dist_dir, "hashes_lancamento.sha256")
shutil.copy2(manifesto_path, manifesto_temp_path)

try:
    # Cria o arquivo ZIP contendo a pasta .dist e o manifesto
    zip_gerado = shutil.make_archive(
        base_name=caminho_zip_base,
        format='zip',
        root_dir=dist_dir
    )
    print(f"\n[SUCESSO] Pacote final gerado em: {zip_gerado}")
except Exception as e:
    print(f"\n[ERRO] Ocorreu um problema ao compactar o arquivo ZIP. Detalhes: {e}")
finally:
    # Limpeza: remove o manifesto temporário da pasta .dist para mantê-la limpa
    if os.path.exists(manifesto_temp_path):
        os.remove(manifesto_temp_path)