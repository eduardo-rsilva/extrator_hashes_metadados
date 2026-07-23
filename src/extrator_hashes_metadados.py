#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ====================================================================
# EXTRATOR DE HASHES E METADADOS (ERS-IC/SP-NIC)
# Copyright (c) 2026 Eduardo Silva. Todos os direitos reservados.
# ====================================================================
# AVISO DE LICENÇA E TERMOS DE USO
#
# Este software e seu código fonte são propriedade intelectual exclusiva
# do autor. O uso deste software é concedido "no estado em que se encontra"
# ("as is"), sem qualquer tipo de garantia, expressa ou implícita.
#
# 1. USO PERMITIDO:
# É concedido o direito de uso gratuito, não-exclusivo e intransferível
# deste software EXCLUSIVAMENTE para:
# a) Uso acadêmico, pesquisa e estudo;
# b) Uso institucional por órgãos de segurança pública, forças policiais,
#    órgãos do poder judiciário e instituições governamentais;
# c) Uso em investigações forenses e elaboração de laudos periciais
#    (incluindo o uso por peritos criminais e assistentes técnicos
#    particulares no exercício de suas funções processuais).
#
# 2. USO PROIBIDO (USO COMERCIAL):
# É terminantemente proibido, sem a autorização prévia e por escrito
# do autor:
# a) Integrar este código ou suas partes em softwares comerciais,
#    produtos pagos ou plataformas como serviço (SaaS);
# b) Vender, revender, alugar ou licenciar este software;
# c) Distribuir versões modificadas deste software ao público sem a
#    manutenção destes avisos de direitos autorais originais.
#
# 3. ISENÇÃO DE RESPONSABILIDADE:
# O autor não se responsabiliza por quaisquer danos diretos, indiretos,
# incidentais ou lucros cessantes resultantes do uso ou da incapacidade
# de uso deste software. A validação da integridade da evidência digital
# é de inteira responsabilidade do usuário final.
# ====================================================================

"""
Extrator de Hashes e Metadados (ERS-IC/SP-NIC)
Versão: 5.3.2
Desenvolvedor: Eduardo Rodrigues da Silva
Contato: rodrigues.ers@policiacientifica.sp.gov.br

Descrição:
    Ferramenta pericial para extração de hashes criptográficos (CRC32, MD5, SHA-1, SHA-256, SHA-384, SHA-512)
    e metadados avançados de uma vasta gama de arquivos (imagens, vídeos, áudios, documentos, executáveis,
    e-mails, atalhos, etc.). Inclui detecção de fluxos de dados ocultos (ADS NTFS), cálculo de entropia de Shannon,
    aquisição forense bit-a-bit de unidades (RAW) com geração de imagem .dd e log de auditoria.

    O programa é desenvolvido para auxiliar a perícia digital, garantindo a integridade das evidências por meio
    de técnicas de leitura somente-leitura, bloqueio de arquivos em uso e detecção de artefatos de nuvem.

    Código aberto para auditoria. Distribuição livre para fins forenses, conforme os termos de licença acima.
"""

import sys
import ctypes

# --- INFORMAÇÕES DO PROGRAMA ---
NOME_APP = "Extrator de Hashes e Metadados (ERS-IC/SP-NIC)"
VERSAO_APP = "5.3.2"
DESENVOLVEDOR = "Eduardo Rodrigues da Silva"
EMAIL_CONTATO = "rodrigues.ers@policiacientifica.sp.gov.br"
USUARIO = "eduardo-rsilva"
REPOSITORIO = "extrator_hashes_metadados"
LINK_GITHUB = f"https://github.com/{USUARIO}/{REPOSITORIO}"
# -------------------------------

DEBUG_MESSAGES = False # USADO APENAS NA FASE DE DESENVOLVIMENTO

INTERVALO_ATUALIZACAO_BARRA_PREVISAO_PROGRESSO_TOTAL = 2 # em segundos

# --- VALIDAÇÃO DE ARQUITETURA ---
if sys.maxsize <= 2**32:
    # Cria uma caixa de mensagem de erro nativa do Windows antes do PySide6 carregar
    import ctypes
    mensagem = (
        "ERRO FATAL: ARQUITETURA INCOMPATÍVEL\n\n"
        f"O {NOME_APP} requer um sistema e interpretador de 64 bits (x64).\n"
        "A execução atual foi detectada como 32 bits (x86).\n\n"
        "Por favor, execute o programa em um ambiente Windows 64-bits."
    )
    # 0x10 = MB_ICONHAND (Ícone de Erro / X Vermelho)
    ctypes.windll.user32.MessageBoxW(0, mensagem, "Erro de Arquitetura", 0x10)
    sys.exit(1)

# ==============================================================================
# IMPORTAÇÃO DAS DEMAIS BIBLIOTECAS (Só ocorre se passou pelo teste de 64-bits acima)
# ==============================================================================

import hashlib
import shutil
import math # Para o cálculo de logaritmo da Entropia
from collections import Counter
import datetime
import json
import msvcrt
from ctypes import wintypes
import os
import winreg
import re
from typing import Any
import subprocess
import traceback
import threading
from cryptography.fernet import Fernet
import zlib
import zipfile
import xml.etree.ElementTree as ET
from email import policy
from email.parser import BytesParser
import datetime as dt # Importado como dt para não conflitar com o datetime existente
from pathlib import Path
from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
                               QPushButton, QCheckBox, QTextEdit, QFileDialog,
                               QProgressBar, QLabel, QMessageBox, QToolTip, QDialog, QComboBox,
                               QTabWidget, QFrame, QGroupBox, QLineEdit, QStackedWidget,
                               QMenuBar, QMenu, QWidgetAction)
from PySide6.QtGui import QIcon, QTextCursor, QAction
from PySide6.QtCore import QTimer, QEvent, QThread, Signal, Qt

# imports para hash bit a bit
import argparse
import tempfile
import uuid
import time

try:
    from hash_fonte import HASH_DO_CODIGO_FONTE
except ImportError:
    # Caso esteja rodando sem compilar (no PyCharm), o arquivo ainda pode não existir
    HASH_DO_CODIGO_FONTE = "Hash indisponível (Execução em modo IDE/Desenvolvimento)"

# Texto da licença (para ser carregado na GUI)
TEXTO_LICENCA = """AVISO DE LICENÇA E TERMOS DE USO

Este software e seu código fonte são propriedade intelectual exclusiva do autor. O uso deste software é concedido "no estado em que se encontra" ("as is"), sem qualquer tipo de garantia, expressa ou implícita.

1. USO PERMITIDO:
É concedido o direito de uso gratuito, não-exclusivo e intransferível deste software EXCLUSIVAMENTE para:
a) Uso acadêmico, pesquisa e estudo;
b) Uso institucional por órgãos de segurança pública, forças policiais, órgãos do poder judiciário e instituições governamentais;
c) Uso em investigações forenses e elaboração de laudos periciais (incluindo o uso por peritos criminais e assistentes técnicos particulares no exercício de suas funções processuais).

2. USO PROIBIDO (USO COMERCIAL):
É terminantemente proibido, sem a autorização prévia e por escrito do autor:
a) Integrar este código ou suas partes em softwares comerciais, produtos pagos ou plataformas como serviço (SaaS);
b) Vender, revender, alugar ou licenciar este software;
c) Distribuir versões modificadas deste software ao público sem a manutenção destes avisos de direitos autorais originais.

3. ISENÇÃO DE RESPONSABILIDADE:
O autor não se responsabiliza por quaisquer danos diretos, indiretos, incidentais ou lucros cessantes resultantes do uso ou da incapacidade de uso deste software em ambientes de produção ou perícia. A validação da integridade da evidência digital é de inteira responsabilidade do usuário final.

Ao utilizar este software, você concorda com estes termos.
"""

# --- TENTATIVA DE IMPORTAR BIBLIOTECAS DE METADADOS ---
try:
    from PIL import Image
    from PIL.ExifTags import GPSTAGS, TAGS

    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    Image = GPSTAGS = TAGS = None

try:
    import cv2

    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False
    cv2 = None

try:
    from pypdf import PdfReader

    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False
    PdfReader = None

try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False
    olefile = None

try:
    import LnkParse3
    HAS_LNKPARSE = True
except ImportError:
    HAS_LNKPARSE = False
    LnkParse3 = None

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    pefile = None

try:
    import extract_msg
    HAS_EXTRACT_MSG = True
except ImportError:
    HAS_EXTRACT_MSG = False
    extract_msg = None

try:
    from tinytag import TinyTag
    HAS_TINYTAG = True
except ImportError:
    HAS_TINYTAG = False
    TinyTag = None

try:
    from pymediainfo import MediaInfo
    HAS_PYMEDIAINFO = True
except ImportError:
    HAS_PYMEDIAINFO = False
    MediaInfo = None

# ------------------------------------------------------

def get_base_dir() -> Path:
    nuitka_onefile_parent = os.environ.get("NUITKA_ONEFILE_PARENT")
    if nuitka_onefile_parent:
        return Path(nuitka_onefile_parent).resolve().parent

    if is_running_compiled():
        return Path(obter_caminho_exe()).resolve().parent

    return Path(__file__).resolve().parent


def obter_caminho_exe() -> str:
    """Obtém o caminho absoluto do .exe via API do Windows, imune a bugs do Nuitka."""
    if os.name == 'nt':
        buf = ctypes.create_unicode_buffer(32768)
        ctypes.windll.kernel32.GetModuleFileNameW(None, buf, 32768)
        return buf.value
    return os.path.abspath(sys.executable)


def is_running_compiled() -> bool:
    """Verifica com precisão se está compilado (PyInstaller ou Nuitka)."""
    if getattr(sys, "frozen", False):
        return True

    # Verifica nos globals ou nos built-ins se o Nuitka injetou a variável
    # (Assim o seu editor de código não apita variável não declarada)
    if "__compiled__" in globals() or hasattr(__builtins__, "__compiled__"):
        return True

    return False



BASE_DIR = get_base_dir()
ICON_PATH = str(BASE_DIR / "app.ico")
MENSAGEM_INICIAL = "Arraste e solte arquivo(s), diretório(s) ou ícones de unidades em qualquer lugar desta janela para extração de HASHES e/ou METADADOS."

# Mensagem em HTML para embelezar a caixa de texto (aceita Modo Escuro automaticamente)
MENSAGEM_VISUAL = f"""
<div style="text-align: center;">
    <span style="font-size: 16pt; font-weight: bold; color: #0078D7;">ÁREA DE EXTRAÇÃO FORENSE</span><br><br>
    <span style="font-size: 11pt;">
        <b>Arraste e solte</b> arquivo(s), diretório(s) ou ícones de unidades<br>
        em qualquer lugar desta área para extração de <b>HASHES</b> e/ou <b>METADADOS</b>.
    </span>
</div>
"""

CONFIG_FILE = BASE_DIR / "config.dat"
KEY = b'cN8vZ8jK8vJk9sLk2jHfGdSdFgJkLmQnRtYwXzPqLmN='
cipher = Fernet(KEY)

# --- LISTAS CENTRALIZADAS DE FORMATOS SUPORTADOS ---
FORMATOS_IMAGEM = [
    '3fr', 'aae', 'ai', 'ait', 'arq', 'arw', 'avif', 'bmp', 'dib', 'bpg', 'btf',
    'c2pa', 'jumbf', 'cos', 'cr2', 'cr3', 'crw', 'ciff', 'cs1', 'dcm', 'dc3',
    'dic', 'dicm', 'dcp', 'dcr', 'djvu', 'djv', 'dng', 'dpx', 'dr4', 'eip',
    'eps', 'epsf', 'ps', 'erf', 'exif', 'exr', 'exv', 'fff', 'fits', 'fla',
    'flif', 'fpf', 'fpx', 'gif', 'gpr', 'hdp', 'wdp', 'jxr', 'hdr', 'heic',
    'heif', 'hif', 'icc', 'icm', 'ico', 'cur', 'iiq', 'ind', 'indd', 'indt',
    'insp', 'j2k', 'jpc', 'j2c', 'jng', 'jp2', 'jpf', 'jpm', 'jpx', 'jpeg',
    'jpg', 'jpe', 'jxl', 'k25', 'kdc', 'key', 'la', 'lrv', 'mef', 'mie',
    'miff', 'mif', 'mng', 'mos', 'mrw', 'neq', 'nef', 'nrw', 'orf', 'ori',
    'pac', 'pcx', 'pef', 'pgm', 'pict', 'pct', 'pic', 'png', 'pnm', 'ppm',
    'psb', 'psd', 'qtk', 'raf', 'raw', 'riq', 'rw2', 'rwl', 'rwz', 'sr2',
    'srf', 'srw', 'svg', 'tiff', 'tif', 'vrd', 'webp', 'x3f', 'xcf', 'xmp'
]

FORMATOS_VIDEO = [
    '3g2', '3gp2', '3gp', '3gpp', 'asf', 'avi', 'crm', 'divx', 'dv', 'dvb',
    'dvr-ms', 'f4p', 'f4v', 'flv', 'glv', 'insv', 'm2t', 'm2ts', 'mts', 'm4v',
    'mkv', 'mov', 'qt', 'mp4', 'mp4v', 'mpeg', 'mpg', 'mpe', 'm2v', 'mxf',
    'ogv', 'rm', 'rv', 'rmvb', 'seq', 'swf', 'ts', 'vob', 'webm', 'wmv', 'xavc'
]

FORMATOS_AUDIO = [
    'aa', 'aax', 'aac', 'aiff', 'aif', 'aifc', 'ape', 'dsf', 'dss', 'ds2',
    'f4a', 'f4b', 'flac', 'm4a', 'm4b', 'm4p', 'mac', 'mid', 'midi', 'mka',
    'mp3', 'mpca', 'ogg', 'oga', 'opus', 'pac', 'ra', 'spx', 'tak', 'wav',
    'wma', 'wv', 'wvc'
]

# --- Subcategorias de Documentos e Outros ---
FORMATOS_PDF = ['pdf']
FORMATOS_OFFICE_XML = ['docx', 'xlsx', 'pptx']
FORMATOS_OFFICE_LEGADO = ['doc', 'xls', 'ppt']
FORMATOS_ATALHOS = ['lnk']
FORMATOS_EXECUTAVEIS = ['exe', 'dll', 'sys']
FORMATOS_EMAIL_EML = ['eml']
FORMATOS_EMAIL_MSG = ['msg']
FORMATOS_COMPACTADOS = ['zip', 'rar', '7z', 'tar', 'gz']
FORMATOS_TORRENT = ['torrent']
FORMATOS_RTF = ['rtf']

FORMATOS_KML = ['kml', 'kmz', 'xml', 'gpx']

# Soma de todas as subcategorias para exibir na Interface do Usuário
FORMATOS_GERAIS = (FORMATOS_PDF + FORMATOS_OFFICE_XML + FORMATOS_OFFICE_LEGADO +
                   FORMATOS_ATALHOS + FORMATOS_EXECUTAVEIS + FORMATOS_EMAIL_EML +
                   FORMATOS_EMAIL_MSG + FORMATOS_COMPACTADOS + FORMATOS_TORRENT + FORMATOS_RTF + FORMATOS_KML)
# ---------------------------------------------------

###################### BLOCO PARA GERAÇÃO DE HASH BIT A BIT DE UNIDADES (INÍCIO) ##########################
kernel32 = ctypes.windll.kernel32
shell32 = ctypes.windll.shell32

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080

DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

def _ctl_code(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method

FILE_DEVICE_DISK = 0x00000007
FILE_DEVICE_VOLUME = 0x00000056
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0

IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = _ctl_code(FILE_DEVICE_VOLUME, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

class GET_LENGTH_INFORMATION(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ulonglong)]  # c_ulonglong (64 bits) em vez de LARGE_INTEGER evita bugs de alinhamento no ctypes

class DISK_EXTENT(ctypes.Structure):
    _fields_ = [
        ("DiskNumber", wintypes.DWORD),
        ("StartingOffset", ctypes.c_ulonglong),
        ("ExtentLength", ctypes.c_ulonglong),
    ]

class VOLUME_DISK_EXTENTS(ctypes.Structure):
    _fields_ = [
        ("NumberOfDiskExtents", wintypes.DWORD),
        ("Extents", DISK_EXTENT * 1),  # placeholder; vamos ler buffer bruto
    ]

# Use ctypes.WinDLL com use_last_error=True para capturar falhas reais
kernel32_le = ctypes.WinDLL("kernel32", use_last_error=True)

CreateFileW = kernel32_le.CreateFileW
CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
    wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
]
CreateFileW.restype = wintypes.HANDLE

ReadFile = kernel32_le.ReadFile
ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
ReadFile.restype = wintypes.BOOL

CloseHandle = kernel32_le.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

DeviceIoControl = kernel32_le.DeviceIoControl
DeviceIoControl.argtypes = [
    wintypes.HANDLE, wintypes.DWORD,
    wintypes.LPVOID, wintypes.DWORD,
    wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID
]
DeviceIoControl.restype = wintypes.BOOL

GetDriveTypeW = kernel32_le.GetDriveTypeW
GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
GetDriveTypeW.restype = wintypes.UINT

def is_elevated() -> bool:
    try:
        # Forma muito mais simples e confiável para .exe
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def traduzir_erro_windows(err_code: int, operacao: str) -> str:
    """Traduz códigos de erro obscuros do Windows para termos forenses claros."""
    erros = {
        1: "Função Inválida: O dispositivo ou sistema de arquivos não suporta esta operação de baixo nível (Pode ser uma unidade de rede ou RAM Disk).",
        2: "Arquivo/Caminho Não Encontrado: O dispositivo físico não foi localizado. Ele pode ter sido ejetado ou a numeração do PhysicalDrive mudou.",
        3: "Caminho Não Encontrado: O volume ou dispositivo não existe mais no sistema.",
        5: "Acesso Negado: O Windows bloqueou a leitura de baixo nível. Causas comuns: Falta de elevação (UAC), disco encriptado (BitLocker) ou bloqueio ativo do Antivírus/EDR.",
        21: "Dispositivo Não Pronto: A unidade não respondeu. Comum em leitores de cartão vazios, unidades virtuais (VHDs) não montadas ou falha lógica.",
        23: "Erro de Dados (CRC): [FALHA DE HARDWARE] Ocorreu um Erro de Verificação Cíclica de Redundância. O disco possui setores fisicamente danificados ou corrupção severa.",
        27: "Setor Não Encontrado: [FALHA DE HARDWARE] A agulha ou controladora não conseguiu localizar o setor físico no disco.",
        32: "Violação de Compartilhamento: Outro processo (ou o próprio Windows) está com acesso exclusivo bloqueando a unidade.",
        433: "Dispositivo Inexistente (NO_SUCH_DEVICE): O hardware foi removido ou desconectado abruptamente (cabo solto/ejetado) no meio da leitura de baixo nível.",
        1117: "Erro de Dispositivo de E/S (I/O): [FALHA CRÍTICA] O dispositivo de armazenamento falhou fisicamente ou a controladora travou durante a transferência de dados.",
        1167: "Dispositivo Não Conectado: O pendrive/disco foi fisicamente removido no meio da operação de leitura."
    }

    descricao = erros.get(err_code, f"Erro desconhecido documentado pela Microsoft.")
    return f"Falha na operação '{operacao}' (Código OS: {err_code}) -> {descricao}"


def obter_info_hardware_por_letra(letra_unidade: str) -> dict:
    """
    Mapeia a letra de unidade para o disco físico e extrai metadados de hardware.
    Não requer privilégios de Administrador.
    """
    letra = letra_unidade.replace(":\\", "").replace(":", "").strip().upper()

    # Script que captura Tipo de Conexão, Nome (Fabricante/Modelo) e Serial
    # Retorna as 3 informações em linhas separadas
    ps_script = (
        f"$disk = Get-Partition -DriveLetter {letra} | Get-Disk; "
        "if ($disk) { "
        "Write-Output $disk.BusType; "
        "Write-Output $disk.FriendlyName; "
        "Write-Output $disk.SerialNumber "
        "}"
    )

    info_hw = {
        "bus_type": "Não detectado",
        "modelo_fabricante": "Não detectado",
        "serial": "Não detectado"
    }

    try:
        resultado = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, creationflags=0x08000000
        )

        # Filtra as linhas de saída vazias
        linhas = [linha.strip() for linha in resultado.stdout.splitlines() if linha.strip()]

        if len(linhas) >= 3:
            info_hw["bus_type"] = linhas[0]
            info_hw["modelo_fabricante"] = linhas[1]
            info_hw["serial"] = linhas[2]

    except Exception:
        pass

    return info_hw


import struct

def identificar_arquitetura_executavel(caminho_arquivo):
    """Lê os cabeçalhos binários puros para identificar a arquitetura real do executável."""
    try:
        with open(caminho_arquivo, 'rb') as f:
            dos_header = f.read(64)
            # Verifica se começa com 'MZ' (Mark Zbikowski - Assinatura clássica do DOS)
            if len(dos_header) < 64 or dos_header[0:2] != b'MZ':
                return None

            # Lê o offset 'e_lfanew' (posição 0x3C) que aponta para o cabeçalho real
            e_lfanew = struct.unpack('<I', dos_header[60:64])[0]

            f.seek(e_lfanew)
            assinatura = f.read(2)

            if assinatura == b'PE':
                return "PE (32/64-bits Moderno)"
            elif assinatura == b'NE':
                return "NE (16-bits Legado - Windows 3.x)"
            elif assinatura == b'LE' or assinatura == b'LX':
                return "LE/LX (OS/2 ou Virtual Device Driver)"
            else:
                return "Assinatura Desconhecida"
    except Exception:
        return None

def open_device_readonly(device_path: str) -> int:
    h = CreateFileW(
        device_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None
    )
    if h == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        msg = traduzir_erro_windows(err, "CreateFileW (Abrir Unidade)")
        raise RuntimeError(f"Erro ao tentar acessar: {device_path}\n{msg}")
    return h

def device_get_length_bytes(handle: int) -> int:
    out = GET_LENGTH_INFORMATION()
    br = wintypes.DWORD(0)
    ok = DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, None, 0, ctypes.byref(out), ctypes.sizeof(out), ctypes.byref(br), None)
    if not ok:
        err = ctypes.get_last_error()
        msg = traduzir_erro_windows(err, "DeviceIoControl (Medir Tamanho)")
        raise RuntimeError(msg)
    return int(out.Length)

# noinspection PyTypeChecker
def volume_to_physical_drives(volume_device: str) -> list[int]:
    h = open_device_readonly(volume_device)
    try:
        buf_size = 4096
        buf = ctypes.create_string_buffer(buf_size)
        br = wintypes.DWORD(0)
        ok = DeviceIoControl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, None, 0, buf, buf_size, ctypes.byref(br), None)
        if not ok:
            err = ctypes.get_last_error()
            raise OSError(err, f"DeviceIoControl(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS) falhou. Erro OS: {err}")

        num = int.from_bytes(buf.raw[0:4], "little", signed=False)
        drives = []
        offset = 8 # Pula o DWORD e o padding para chegar no array de extents (alinhamento de 64 bits)
        extent_size = ctypes.sizeof(DISK_EXTENT)
        for _ in range(num):
            ext = DISK_EXTENT.from_buffer_copy(buf.raw[offset:offset+extent_size])
            drives.append(int(ext.DiskNumber))
            offset += extent_size
        return sorted(set(drives))
    finally:
        CloseHandle(h)


def obter_serial_hardware(disk_number) -> str:
    """
    Busca o serial físico do dispositivo.
    Se o SerialNumber padrão for vazio (comum em pendrives USB),
    extrai o serial do PNPDeviceID (Plug and Play).
    """
    # 1. Garante que temos apenas o número do disco (trata tanto "9" quanto "\\.\PHYSICALDRIVE9")
    match = re.search(r'\d+', str(disk_number))
    if not match:
        return "Indisponível (Índice não encontrado)"

    disk_index = match.group(0)

    try:
        creationflags = 0x08000000 if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0

        # 2. Script PowerShell que busca o Serial.
        # Se for vazio, pega o PNPDeviceID, corta a parte final e remove o sufixo "&0" do Windows.
        ps_script = (
            f"$d = Get-WmiObject Win32_DiskDrive -Filter 'Index={disk_index}'; "
            f"if ($d.SerialNumber -and $d.SerialNumber.Trim() -ne '') {{ "
            f"    Write-Output $d.SerialNumber.Trim() "
            f"}} elseif ($d.PNPDeviceID) {{ "
            f"    $parts = $d.PNPDeviceID -split '\\\\'; "
            f"    $id = $parts[-1]; "
            f"    if ($id -match '&') {{ $id = ($id -split '&')[0] }}; "
            f"    Write-Output $id "
            f"}}"
        )

        resultado = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, creationflags=creationflags
        )

        serial = resultado.stdout.strip()

        # 3. Retorna o serial, ou um aviso claro se tudo falhar (não retorna vazio)
        if serial:
            return serial

    except Exception:
        pass

    return "Não detectado / Indisponível"

def normalize_drive_root(drive_letter: str) -> str:
    d = drive_letter.strip().replace("/", "\\")
    if len(d) >= 2 and d[1] == ":":
        return d[0].upper() + ":\\"
    raise ValueError("Drive inválido (use tipo E: ou E:\\)")

def drive_root_to_volume_device(drive_root: str) -> str:
    # "E:\\" -> "\\\\.\\E:"
    return r"\\.\{}".format(drive_root[0].upper() + ":")

def get_drive_type(drive_root: str) -> int:
    return int(GetDriveTypeW(wintypes.LPCWSTR(drive_root)))

def is_device_cdrom(device_path: str) -> bool:
    """Detecta de forma robusta se a unidade/caminho selecionado pertence a um CD/DVD (Mídia Óptica)."""
    s = device_path.strip().upper()
    # 1. Checa se o caminho contém uma letra de volume (Ex: \\.\E: ou E:\) e valida com a API
    match = re.search(r'([A-Z]):', s)
    if match:
        letra = match.group(1)
        return get_drive_type(f"{letra}:\\") == DRIVE_CDROM
    # 2. Fallback para nomes de dispositivos físicos ópticos nativos do Windows
    if s.startswith("\\\\.\\CDROM"):
        return True
    return False

def parse_algos_csv(csv_text: str) -> list[str]:
    items = []
    for part in (csv_text or "").split(","):
        s = part.strip().upper()
        if s:
            items.append(s)
    return items

def init_hash_objects(algos: list[str]):
    h = {}
    if "CRC32" in algos:
        h["CRC32"] = 0
    if "MD5" in algos:
        h["MD5"] = hashlib.md5()
    if "SHA-1" in algos:
        h["SHA-1"] = hashlib.sha1()
    if "SHA-256" in algos:
        h["SHA-256"] = hashlib.sha256()
    if "SHA-384" in algos:
        h["SHA-384"] = hashlib.sha384()
    if "SHA-512" in algos:
        h["SHA-512"] = hashlib.sha512()
    return h

def finalize_hashes(hash_objs: dict):
    out = {}
    for k, v in hash_objs.items():
        if k == "CRC32":
            out["CRC32"] = f"{(v & 0xFFFFFFFF):08X}"
        else:
            out[k] = v.hexdigest().upper()
    return out

def raw_hash_device(
        device_path: str,
        algos: list[str],
        chunk_size: int,
        progress_json_path: str | None,
        cancel_flag_path: str | None,
        image_out_path: str | None = None
) -> dict:
    if not algos:
        raise ValueError("Nenhum algoritmo selecionado")

    h = open_device_readonly(device_path)

    # Prepara o arquivo de imagem de destino
    f_img = None
    if image_out_path:
        os.makedirs(os.path.dirname(os.path.abspath(image_out_path)), exist_ok=True)
        f_img = open(image_out_path, "wb")

    # Prepara variáveis de resultado fora do try
    total = 0
    bytes_read_total = 0
    hash_objs = {}

    # Prepara variáveis de resultado fora do try
    total = 0
    bytes_read_total = 0
    hash_objs = {}

    try:
        total = device_get_length_bytes(h)
        hash_objs = init_hash_objects(algos)
        buf = ctypes.create_string_buffer(chunk_size)

        last_progress_write = 0.0
        last_cancel_check = 0.0  # <--- variável para controle de tempo

        while bytes_read_total < total:
            now = time.time()

            # --- VERIFICAÇÃO DE CANCELAMENTO OTIMIZADA ---
            # Checa o disco no máximo 2 vezes por segundo (a cada 0.5s),
            # em vez de checar a cada chunk de 1MB lido
            if cancel_flag_path and (now - last_cancel_check) >= 0.5:
                last_cancel_check = now
                if os.path.exists(cancel_flag_path):
                    return {
                        "bytes_total": total,
                        "bytes_read": bytes_read_total,
                        "hashes": {},
                        "cancelado": True
                    }

            to_read = chunk_size

            remaining = total - bytes_read_total
            if remaining < to_read:
                to_read = int(remaining)

            br = wintypes.DWORD(0)
            ok = ReadFile(h, buf, to_read, ctypes.byref(br), None)

            if not ok:
                err = ctypes.get_last_error()
                msg = traduzir_erro_windows(err, f"ReadFile (Lendo byte {bytes_read_total})")
                raise RuntimeError(msg)

            n = int(br.value)
            if n <= 0:
                break

            data = buf.raw[:n]

            # --- SALVA O BLOCO NA IMAGEM FORENSE ---
            if f_img:
                f_img.write(data)
            # ---------------------------------------------

            for algo, obj in hash_objs.items():
                if algo == "CRC32":
                    hash_objs["CRC32"] = zlib.crc32(data, hash_objs["CRC32"])
                else:
                    obj.update(data)

            bytes_read_total += n

            now = time.time()
            if progress_json_path and (now - last_progress_write) >= INTERVALO_ATUALIZACAO_BARRA_PREVISAO_PROGRESSO_TOTAL:
                pct = int((bytes_read_total / total) * 100) if total else 0
                tmp = {
                    "device": device_path,
                    "bytes_total": total,
                    "bytes_read": bytes_read_total,
                    "percent": pct,
                    "ts": now,
                }
                try:
                    os.makedirs(os.path.dirname(progress_json_path), exist_ok=True)
                    with open(progress_json_path, "w", encoding="utf-8") as f:
                        json.dump(tmp, f, ensure_ascii=False)
                except Exception:
                    pass
                last_progress_write = now

        # Retorno normal (sucesso absoluto)
        return {
            "device": device_path,
            "bytes_total": total,
            "bytes_read": bytes_read_total,
            "hashes": finalize_hashes(hash_objs),
            "cancelado": False
        }

    finally:
        # O finally sempre rodará, fechando a alça do disco, não importa como saiu.
        CloseHandle(h)
        if f_img:
            f_img.close()  # Garante que o arquivo da imagem seja fechado.

def _raw_lock_key_from_device(device_path: str) -> list[str]:
    """Descobre os discos físicos reais associados ao caminho selecionado."""
    s = (device_path or "").upper().strip()

    # 1. Se já for um disco físico (ex: \\.\PhysicalDrive0)
    if s.startswith("\\\\.\\PHYSICALDRIVE"):
        n = "".join(ch for ch in s.split("PHYSICALDRIVE", 1)[1] if ch.isdigit())
        if n:
            return [f"PD_{n}"]

    # 2. Se for um volume lógico (ex: \\.\C:)
    elif s.startswith("\\\\.\\") and len(s) >= 6 and s[5] == ":":
        try:
            # Usa sua função nativa para descobrir de qual disco físico esse volume faz parte
            drives = volume_to_physical_drives(device_path)
            if drives:
                # Se o volume for um RAID, pode estar em mais de um disco, retorna todos
                return [f"PD_{d}" for d in drives]
        except Exception:
            pass

    # 3. Fallback (unidades de rede mapeadas, pendrives não identificáveis, etc)
    safe = "".join(ch if ch.isalnum() else "_" for ch in s)
    return [f"DEV_{safe[:40]}"]


def try_acquire_raw_device_lock(device_path: str):
    """Tenta travar todos os discos físicos base associados à unidade requerida."""
    keys = _raw_lock_key_from_device(device_path)
    acquired_files = []

    for key in keys:
        lock_path = os.path.join(tempfile.gettempdir(), f"ERS_IC_NIC_RAW_LOCK_{key}.lock")
        try:
            f = open(lock_path, "a+b")
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)  # Falha imediato se ocupado
            acquired_files.append(f)
        except OSError:
            # Se falhou ao travar este disco, SOLTA todos os outros que já tinha conseguido antes de negar
            release_raw_device_lock(acquired_files)
            return None, lock_path

    return acquired_files, "locked"


def release_raw_device_lock(files_list):
    """Libera todos os locks adquiridos."""
    if not files_list:
        return

    # Garante que funciona caso passe um único arquivo ou uma lista
    if not isinstance(files_list, list):
        files_list = [files_list]

    for f in files_list:
        try:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
        try:
            f.close()
        except Exception:
            pass


def _build_runas_command_args(params_list: list[str]) -> str:
    """
    Constrói a string de argumentos para o ShellExecuteW no Windows.
    Garante o quoting correto de caminhos com espaços e previne a quebra
    do comando por barras invertidas no final de diretórios.
    """
    args = []

    for item in params_list:
        # Garante a conversão caso a lista contenha objetos pathlib.Path
        param = str(item)

        # Parâmetros vazios devem ser passados explicitamente como strings vazias
        if not param:
            args.append('""')
            continue

        # Se houver espaços, tabulações ou aspas, precisamos de tratamento especial
        if ' ' in param or '\t' in param or '"' in param:
            # 1. Escapa aspas duplas internas já existentes
            param_escaped = param.replace('"', '\\"')

            # 2. CORREÇÃO CRUCIAL PARA O WINDOWS:
            # Se a string terminar com barra invertida, duplicamos a barra final.
            # Isso impede que a barra escape a aspa dupla de fechamento.
            if param_escaped.endswith('\\'):
                param_escaped += '\\'

            args.append(f'"{param_escaped}"')
        else:
            args.append(param)

    return " ".join(args)


def relancar_elevado(params_list: list[str]) -> int:
    # Retorna o código rc inteiro, em vez de um booleano (rc > 32)
    if is_running_compiled():
        exe = obter_caminho_exe()
        args = _build_runas_command_args(params_list)
    else:
        exe = os.path.abspath(sys.executable)
        script = os.path.abspath(__file__)
        args = _build_runas_command_args([script] + params_list)

    rc = shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
    return rc  # Vai retornar >32 se sucesso, ou o código de erro



def run_raw_helper_elevated(
        device_path: str,
        algos: list[str],
        chunk_size: int,
        out_json_path: str,
        progress_json_path: str,
        cancel_flag_path: str,
        image_out_path: str = ""
) -> int:
    params = [
        "--raw-hash",
        "--device", device_path,
        "--algos", ",".join(algos),
        "--chunk", str(int(chunk_size)),
        "--out-json", out_json_path,
        "--progress-json", progress_json_path,
        "--cancel-flag", cancel_flag_path,
    ]
    if image_out_path:
        params.extend(["--image-out", image_out_path])

    if is_elevated():
        if is_running_compiled():
            exe = obter_caminho_exe()
            cmd = [exe] + params
        else:
            exe = os.path.abspath(sys.executable)
            script = os.path.abspath(__file__)
            cmd = [exe, script] + params

        creationflags = 0
        if os.name == 'nt':
            creationflags = 0x08000000  # CREATE_NO_WINDOW

        subprocess.Popen(cmd, creationflags=creationflags)
        return 42 # Qualquer número > 32 significa sucesso

    return relancar_elevado(params)


def cli_raw_mode_main(argv=None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--raw-hash", action="store_true")
    parser.add_argument("--device", default="")
    parser.add_argument("--algos", default="SHA-256,SHA-512")
    parser.add_argument("--chunk", type=int, default=1024 * 1024)
    parser.add_argument("--out-json", default="")
    parser.add_argument("--progress-json", default="")
    parser.add_argument("--cancel-flag", default="")
    parser.add_argument("--image-out", default="")
    args, _ = parser.parse_known_args(argv)

    if not args.raw_hash:
        return 0

    # Este caminho precisa rodar elevado para abrir PhysicalDrive/volume raw
    if os.name != "nt":
        raise SystemExit("RAW só é suportado no Windows")

    algos = parse_algos_csv(args.algos)
    out_path = args.out_json.strip()
    prog_path = args.progress_json.strip() or None
    cancel_path = args.cancel_flag.strip() or None

    if not out_path:
        raise SystemExit("Parâmetro --out-json é obrigatório")

    img_out = args.image_out.strip() or None

    # VALIDAÇÃO DE SEGURANÇA: Aborta a operação se o escopo exigido for hardware (PhysicalDrive) em mídia óptica
    is_hardware_scope = args.device.upper().startswith("\\\\.\\PHYSICALDRIVE")
    if is_hardware_scope and is_device_cdrom(args.device):
        payload = {"ok": False,
                   "error": "OPERAÇÃO ABORTADA: A extração física de hardware não é suportada nativamente em mídias ópticas (CD/DVD). O acesso deve ser feito pelo volume lógico."}
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return 0

    lock_f = None
    try:
        lock_f, lock_path = try_acquire_raw_device_lock(args.device)
        if lock_f is None:
            payload = {
                "ok": False,
                "error": f"JÁ EXISTE AQUISIÇÃO RAW EM ANDAMENTO PARA ESTE DRIVE: {args.device}"
            }
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            return 0

        res = raw_hash_device(
            device_path=args.device,
            algos=algos,
            chunk_size=max(4096, int(args.chunk)),
            progress_json_path=prog_path,
            cancel_flag_path=cancel_path,
            image_out_path=img_out
        )
        if res.get("cancelado"):
            payload = {"ok": False, "error": "OPERAÇÃO CANCELADA PELO USUÁRIO"}
        else:
            payload = {"ok": True, "result": res}
    except Exception as e:
        payload = {"ok": False, "error": repr(e)}

    finally:
        if lock_f:
            release_raw_device_lock(lock_f)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    return 0

###################### BLOCO PARA GERAÇÃO DE HASH BIT A BIT DE UNIDADES (FIM) #############################

# --- FUNÇÃO PARA LOCALIZAR O EXIFTOOL ---
def obter_caminho_exiftool():
    """
    Retorna o caminho do ExifTool (exclusivo para 64 bits).
    Procura tanto no diretório base do script quanto um nível acima.
    """
    pasta_exiftool = "exiftool-13.59_64"
    nome_executavel = "exiftool.exe"

    # Define os possíveis locais de busca (dentro da pasta .dist ou na raiz do projeto)
    caminhos_tentativa = [
        BASE_DIR / pasta_exiftool / nome_executavel,
        BASE_DIR.parent / pasta_exiftool / nome_executavel
    ]

    for caminho in caminhos_tentativa:
        if caminho.exists():
            return str(caminho)

    return None


def obter_caminho_ewfacquire():
    """Procura o ewfacquire.exe na pasta 'ewf' ou na raiz do script."""
    nome_executavel = "ewfacquire.exe"
    caminhos_tentativa = [
        BASE_DIR / "ewf" / nome_executavel,
        BASE_DIR / nome_executavel,
        BASE_DIR / "bin" / nome_executavel
    ]
    for caminho in caminhos_tentativa:
        if caminho.exists():
            return str(caminho)
    return None

def obter_caminho_ewfverify():
    """Procura o ewfverify.exe na pasta 'ewf' ou na raiz do script."""
    nome_executavel = "ewfverify.exe"
    caminhos_tentativa = [
        BASE_DIR / "ewf" / nome_executavel,
        BASE_DIR / nome_executavel,
        BASE_DIR / "bin" / nome_executavel
    ]
    for caminho in caminhos_tentativa:
        if caminho.exists():
            return str(caminho)
    return None


def verificar_integridade_automatica(caminho_imagem_e01, hash_sha256_log):
    """Roda o ewfverify em um terminal visível nativo e resolve o erro de UTF-16 do PowerShell."""
    caminho_ewfverify = obter_caminho_ewfverify()
    if not caminho_ewfverify:
        return False, "   ⚠️ Erro: O executável 'ewfverify.exe' não foi localizado. Validação automática pulada."

    # LIMPEZA DO CAMINHO: Força o uso estrito de barras invertidas (\) e resolve o caminho absoluto
    caminho_limpo = os.path.normpath(os.path.abspath(caminho_imagem_e01))
    comando_str = f'"{caminho_ewfverify}" -d md5,sha256 "{caminho_limpo}"'

    # Arquivo temporário para guardar a saída do terminal
    caminho_log_temp = caminho_limpo + ".verify_temp.txt"

    # O Tee-Object joga a saída na tela do PowerShell e salva no arquivo simultaneamente
    comando_ps = f'& "{caminho_ewfverify}" -d md5,sha256 "{caminho_limpo}" | Tee-Object -FilePath "{caminho_log_temp}"'
    comando = ["powershell", "-NoProfile", "-Command", comando_ps]

    try:
        # 0x00000010 = CREATE_NEW_CONSOLE (Força o Windows a abrir a janela do terminal para o perito)
        creationflags = 0x00000010 if os.name == 'nt' else 0

        processo = subprocess.Popen(comando, creationflags=creationflags)

        # Pulmão da interface principal enquanto o terminal trabalha
        while processo.poll() is None:
            QApplication.processEvents()
            time.sleep(0.1)

        # Lê o log bruto em BYTES para remover os Null Bytes injetados pelo UTF-16 do PowerShell
        saida_terminal = ""
        if os.path.exists(caminho_log_temp):
            with open(caminho_log_temp, "rb") as f:
                raw_bytes = f.read()
                # Essa linha mágica conserta o Clipboard do Windows e o formato da string!
                saida_terminal = raw_bytes.replace(b'\x00', b'').decode('utf-8', errors='ignore')

            # Apaga o arquivo temporário silenciosamente
            try:
                os.remove(caminho_log_temp)
            except Exception:
                pass

        match = re.search(r"SHA256 hash calculated over data:\s+([a-fA-F0-9]{64})", saida_terminal, re.IGNORECASE)
        match_md5 = re.search(r"MD5 hash calculated over data:\s+([a-fA-F0-9]{32})", saida_terminal, re.IGNORECASE)

        if match:
            hash_recalculado = match.group(1).upper()
            hash_original = hash_sha256_log.upper()
            md5_recalc = match_md5.group(1).upper() if match_md5 else "N/A"

            if hash_recalculado == hash_original:
                return True, f"   ✅ INTEGRIDADE CONFIRMADA MATEMATICAMENTE VIA EWFVERIFIY\n   Comando executado: {comando_str}\n   MD5 Recalculado:     {md5_recalc}\n   SHA-256 Recalculado: {hash_recalculado}"
            else:
                return False, f"   ❌ ALERTA CRÍTICO: QUEBRA DE INTEGRIDADE!\n   Comando: {comando_str}\n   SHA-256 Original:    {hash_original}\n   SHA-256 Recalculado: {hash_recalculado}"
        else:
            return False, f"   ⚠️ Erro: Não foi possível localizar a linha do SHA-256.\n\n--- SAÍDA BRUTA DO EWFVERIFY ---\n{saida_terminal}\n--------------------------------"

    except Exception as e:
        return False, f"   ⚠️ Erro crítico na execução do ewfverify: {e}"


def executar_aquisicao_e01_ewf(device_path, caminho_destino, metadados):
    """Executa o ewfacquire com UAC, corrigindo caminhos e mantendo a GUI fluida."""
    caminho_ewf = obter_caminho_ewfacquire()
    if not caminho_ewf:
        raise FileNotFoundError("O executável 'ewfacquire.exe' não foi localizado.")

    if metadados is None:
        metadados = {}

    if caminho_destino.lower().endswith('.e01'):
        caminho_destino = caminho_destino[:-4]

    # CORREÇÃO 1: Normaliza o caminho para forçar o uso exclusivo de barras invertidas (\)
    # Isso evita o erro "\\?\D:\/" no C++ do ewfacquire
    caminho_destino = os.path.normpath(caminho_destino)
    caminho_ewf_norm = os.path.normpath(caminho_ewf)

    # Criamos o caminho do log baseado no caminho de destino
    caminho_log_ewf = f"{caminho_destino}.ewf.log"

    def higienizar_ewf(texto, max_len):
        """Limpa o texto para não quebrar a sintaxe da linha de comando do Windows e do ewfacquire."""
        if not texto: return ""

        # 1. Trunca o tamanho de acordo com o limite seguro passado para cada campo
        texto = texto[:max_len]

        # 2. Remove quebras de linha reais (o ewfacquire via CLI não lida bem com multiline)
        # Substituímos por um traço para manter legibilidade
        texto = texto.replace('\n', ' - ').replace('\r', '')

        # 3. Escapa aspas duplas (para não quebrar o envelopamento do argumento)
        texto = texto.replace('"', '\\"')

        # 4. Escapa aspas simples para o PowerShell
        texto = texto.replace("'", "''")

        # 5. Previne que uma barra invertida no final engula a aspa de fechamento do Windows
        if texto.endswith('\\'):
            texto += '\\'

        return texto

    def escapar_ps(texto):
        """Escapa aspas simples para inserção segura de caminhos de arquivo no PowerShell."""
        return texto.replace("'", "''")

    args = [
        "-u",
        "-c", "fast",
        "-t", f'"{caminho_destino}"',
        "-l", f'"{caminho_log_ewf}"',  # Ativa a gravação do log físico
        "-d", "sha256"  # -d (Digest) adiciona o SHA-256 ao lado do MD5 padrão
    ]

    # Define o tamanho máximo de cada fragmento (.e01, .e02) ---
    tamanho_split = metadados.get("split", "")
    if tamanho_split:
        args.extend(["-S", tamanho_split])
    # -------------------------------------------------------------------

    # Distribuímos limites seguros: 1500 para descrição (que é mais longa) e 255 para campos curtos.
    # Total máximo no pior cenário: ~2265 caracteres, muito seguro para o limite de 8191 do Windows.
    caso = higienizar_ewf(metadados.get("caso", "").strip(), 255)
    if caso: args.extend(["-C", f'"{caso}"'])

    descricao = higienizar_ewf(metadados.get("descricao", "").strip(), 1500)
    if descricao: args.extend(["-D", f'"{descricao}"'])

    laudo = higienizar_ewf(metadados.get("laudo", "").strip(), 255)
    if laudo: args.extend(["-E", f'"{laudo}"'])

    perito = higienizar_ewf(metadados.get("perito", "").strip(), 255)
    if perito: args.extend(["-e", f'"{perito}"'])

    args.append(device_path)

    args_str = " ".join(args)
    caminho_ewf_ps = escapar_ps(str(caminho_ewf_norm))

    # Removemos o cmd /k. Agora ele fecha sozinho quando terminar a extração.
    # Adicionamos um bloco try/catch nativo do PowerShell. Se o UAC for negado, ele força a saída com erro (código 1).
    ps_cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        f"try {{ $p = Start-Process -FilePath '{caminho_ewf_ps}' -ArgumentList '{args_str}' -Verb RunAs -Wait -PassThru -ErrorAction Stop; if ($null -ne $p) {{ exit $p.ExitCode }} else {{ exit 1 }} }} catch {{ exit 1 }}"
    ]

    creationflags = 0x08000000 if os.name == 'nt' else 0

    # CORREÇÃO 2: Usa Popen em vez de run para não bloquear o Python
    processo = subprocess.Popen(ps_cmd, creationflags=creationflags)

    # CORREÇÃO 3: O "Pulmão" da Interface. Mantém o PySide vivo e clicável.
    while processo.poll() is None:
        QApplication.processEvents()
        time.sleep(0.1)  # Pausa rápida para não fritar o processador (CPU)

    if processo.returncode != 0:
        raise RuntimeError(
            f"Processo abortado pelo usuário no UAC ou falha no ewfacquire.\n"
            f"Código retornado: {processo.returncode}"
        )
    return True


def salvar_config(config):
    """Serializa e salva config criptografada."""
    try:
        dados_json = json.dumps(config).encode('utf-8')
        dados_cripto = cipher.encrypt(dados_json)
        with open(CONFIG_FILE, 'wb') as f:
            f.write(dados_cripto)
    except Exception as e:
        print(f"Erro ao salvar config: {e}")

def carregar_config():
    """Carrega e descriptografa a configuração, retorna dict vazio se falhar."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, 'rb') as f:
            dados_cripto = f.read()
        dados_json = cipher.decrypt(dados_cripto)
        return json.loads(dados_json.decode('utf-8'))
    except Exception:
        return {}

def detectar_ads_windows(caminho_arquivo):
    """Detecta a presença de Alternate Data Streams (ADS) em arquivos NTFS."""
    if os.name != 'nt':
        return []

    streams_ocultos = []

    # Estrutura WIN32_FIND_STREAM_DATA da API do Windows
    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [
            ("StreamSize", wintypes.LARGE_INTEGER),
            ("cStreamName", wintypes.WCHAR * 296)
        ]

    kernel32 = ctypes.windll.kernel32

    # --- Definindo explicitamente os tipos de argumentos e retorno ---
    # Isso evita o Access Violation por truncamento de ponteiros em sistemas 64 bits
    kernel32.FindFirstStreamW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,    # STREAM_INFO_LEVELS
        ctypes.c_void_p, # LPVOID lpFindStreamData
        wintypes.DWORD   # DWORD dwFlags
    ]
    kernel32.FindFirstStreamW.restype = ctypes.c_void_p # Retorna um HANDLE (ponteiro)

    kernel32.FindNextStreamW.argtypes = [
        ctypes.c_void_p, # HANDLE
        ctypes.c_void_p  # LPVOID lpFindStreamData
    ]
    kernel32.FindNextStreamW.restype = wintypes.BOOL

    kernel32.FindClose.argtypes = [ctypes.c_void_p]
    kernel32.FindClose.restype = wintypes.BOOL
    # ---------------------------------------------------------------------------

    FindExInfoStandard = 0
    find_data = WIN32_FIND_STREAM_DATA()

    # Inicia a busca por streams no arquivo
    handle = kernel32.FindFirstStreamW(
        wintypes.LPCWSTR(caminho_arquivo),
        FindExInfoStandard,
        ctypes.byref(find_data),
        0
    )

    # Captura o valor exato de INVALID_HANDLE_VALUE para a arquitetura atual
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    # Verifica se o handle é válido antes de prosseguir
    if handle and handle != INVALID_HANDLE_VALUE:
        try:
            teve_ads_suspeito = False
            textos_ads = []

            while True:
                nome_stream = find_data.cStreamName

                # Ignora o stream de dados padrão do Windows (::$DATA)
                if nome_stream != "::$DATA":
                    tamanho = find_data.StreamSize
                    explicacao = ""

                    # 1. Identifica os tipos mais comuns de ADS e gera uma explicação
                    if ":Zone.Identifier" in nome_stream:
                        explicacao = " (Mark of the Web: Indica que o arquivo foi baixado da internet/rede externa.)"
                    elif "SmartScreen" in nome_stream:
                        explicacao = " (Dados de verificação de segurança do Windows Defender SmartScreen.)"
                    elif "encryptable" in nome_stream:
                        explicacao = " (Relacionado a criptografia do Windows, como BitLocker ou EFS.)"
                    elif "favicon" in nome_stream.lower():
                        explicacao = " (Metadados de ícone salvos por navegadores de internet.)"
                    else:
                        explicacao = " (⚠️ ORIGEM DESCONHECIDA. Pode ser metadado de software ou payload malicioso oculto.)"
                        # Se não for nenhum dos conhecidos acima, ativa o gatilho de alerta!
                        teve_ads_suspeito = True

                    texto_atual = f"ADS Oculto: {nome_stream} ({tamanho} bytes){explicacao}"

                    # 2. Tenta ler o conteúdo interno do ADS se for pequeno (< 50 KB)
                    if 0 < tamanho < 51200:
                        try:
                            # O caminho do stream é a junção do arquivo base + o nome do stream
                            caminho_stream = f"{caminho_arquivo}{nome_stream}"

                            # Abre em modo texto, ignorando erros se for um arquivo binário
                            with open(caminho_stream, 'r', encoding='utf-8', errors='ignore') as f:
                                # Lê o limite definido (500)
                                texto_lido = f.read(500)

                                # Verifica se o corte REALMENTE ocorreu LOGO APÓS ler (antes de qualquer tradução ou strip)
                                foi_cortado = (len(texto_lido) == 500)

                                conteudo = texto_lido.strip()

                                if conteudo:
                                    # --- TRADUÇÃO DOS CÓDIGOS DE ZONA DO WINDOWS ---
                                    if "ZoneId=" in conteudo:
                                        dicionario_zonas = {
                                            "0": "[Origem: Computador Local]",
                                            "1": "[Origem: Intranet Local]",
                                            "2": "[Origem: Sites Confiáveis]",
                                            "3": "[Origem: Internet / Download Externo]",
                                            "4": "[Origem: Sites Restritos]"
                                        }
                                        for id_zona, descricao in dicionario_zonas.items():
                                            conteudo = conteudo.replace(f"ZoneId={id_zona}",
                                                                        f"ZoneId={id_zona} {descricao}")
                                    # -----------------------------------------------

                                    # Formata a saída para ficar indentada no relatório
                                    conteudo_formatado = conteudo.replace('\n', '\n       ')
                                    texto_atual += f"\n   ↳ Conteúdo extraído:\n       {conteudo_formatado}"

                                    # --- AVISO DE CORTE E COMANDO POWERSHELL ---
                                    if foi_cortado:
                                        # Divide a string ":Zone.Identifier:$DATA" pelos ":" e pega apenas o nome real
                                        partes_nome = nome_stream.split(":")
                                        nome_limpo_ps = partes_nome[1] if len(partes_nome) > 1 else nome_stream
                                        nome_arquivo_isolado = os.path.basename(caminho_arquivo)

                                        texto_atual += f"\n\n   ↳ [AVISO: O conteúdo excedeu o limite de leitura e foi truncado.]"
                                        texto_atual += f"\n   ↳ Para extrair e ver o conteúdo completo no PowerShell, navegue até a pasta do arquivo e use o comando:"
                                        texto_atual += f"\n       Get-Content -Path \"{nome_arquivo_isolado}\" -Stream \"{nome_limpo_ps}\""
                                    # -----------------------------------------------

                                else:
                                    texto_atual += "\n   ↳ [Conteúdo vazio ou formato binário não legível]"
                        except Exception as e:
                            texto_atual += f"\n   ↳ [Erro ao tentar ler conteúdo: {e}]"

                    elif tamanho >= 51200:
                        # Repete a lógica de limpeza do nome do fluxo para o PowerShell
                        partes_nome = nome_stream.split(":")
                        nome_limpo_ps = partes_nome[1] if len(partes_nome) > 1 else nome_stream
                        nome_arquivo_isolado = os.path.basename(caminho_arquivo)

                        texto_atual += "\n   ↳ [Conteúdo muito grande para exibição em texto. Recomenda-se extração manual.]"
                        texto_atual += f"\n   ↳ Para extrair e ver o conteúdo completo no PowerShell, navegue até a pasta do arquivo e use o comando:"
                        texto_atual += f"\n       Get-Content -Path \"{nome_arquivo_isolado}\" -Stream \"{nome_limpo_ps}\""
                        texto_atual += f"\n   ↳ (Dica: Adicione `> arquivo_extraido.bin` no final do comando para salvá-lo em disco)"

                    # Adiciona esse ADS na lista temporária
                    textos_ads.append(texto_atual)

                # Vai para o próximo stream
                if not kernel32.FindNextStreamW(handle, ctypes.byref(find_data)):
                    break
        finally:
            kernel32.FindClose(handle)

        # 3. Monta o bloco final adicionando o alerta geral apenas se necessário
        if textos_ads:
            streams_ocultos.append("⚠️ AVISO NTFS: Fluxos de Dados Ocultos (ADS) detectados!")

            if teve_ads_suspeito:
                streams_ocultos.append(
                    "   ↳ ALERTA PERICIAL: Foi detectado um fluxo anormal. Verifique possível ocultação de dados ou malware.")
            else:
                streams_ocultos.append(
                    "   ↳ Nota: Apenas marcações normais do sistema/navegador foram encontradas neste arquivo.")

            # Junta os textos lidos com o aviso principal
            streams_ocultos.extend(textos_ads)

    return streams_ocultos


def formatar_bytes_dinamico(tamanho_bytes: int) -> str:
    """Converte bytes para a unidade de medida mais adequada (KB, MB, GB, TB)."""
    if not isinstance(tamanho_bytes, (int, float)) or tamanho_bytes == 0:
        return "0 B"

    unidades = ["B", "KB", "MB", "GB", "TB", "PB"]
    indice = 0
    valor = float(tamanho_bytes)

    while valor >= 1024 and indice < len(unidades) - 1:
        valor /= 1024
        indice += 1

    # Retorna formatado com vírgula no padrão brasileiro
    return f"{valor:.2f}".replace(".", ",") + f" {unidades[indice]}"


def obter_info_volume(caminho):
    """Obtém o rótulo (Label), Serial, Sistema de Arquivos e Capacidade da unidade selecionada."""
    if os.name != 'nt':
        return None

    try:
        # Garante o formato "E:\" que a API do Windows exige
        drive = os.path.splitdrive(caminho)[0] + "\\"

        MAX_PATH = 260
        volume_name_buffer = ctypes.create_unicode_buffer(MAX_PATH + 1)
        file_system_name_buffer = ctypes.create_unicode_buffer(MAX_PATH + 1)
        serial_number = wintypes.DWORD()
        max_component_length = wintypes.DWORD()
        file_system_flags = wintypes.DWORD()

        kernel32 = ctypes.windll.kernel32

        # 1. Tenta obter Rótulo, Serial e FS
        sucesso = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(drive),
            volume_name_buffer,
            ctypes.sizeof(volume_name_buffer),
            ctypes.byref(serial_number),
            ctypes.byref(max_component_length),
            ctypes.byref(file_system_flags),
            file_system_name_buffer,
            ctypes.sizeof(file_system_name_buffer)
        )

        # 2. Tenta obter o tamanho total da unidade
        total_bytes = ctypes.c_ulonglong(0)
        free_bytes_caller = ctypes.c_ulonglong(0)
        free_bytes_total = ctypes.c_ulonglong(0)

        sucesso_tamanho = kernel32.GetDiskFreeSpaceExW(
            ctypes.c_wchar_p(drive),
            ctypes.byref(free_bytes_caller),
            ctypes.byref(total_bytes),
            ctypes.byref(free_bytes_total)
        )

        # Identifica se é uma mídia óptica (DRIVE_CDROM = 5)
        tipo_unidade = kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive))

        # Formata o texto de capacidade
        if sucesso_tamanho and total_bytes.value > 0:
            tamanho_bytes = total_bytes.value

            # Usa a nova função dinâmica
            tamanho_dinamico = formatar_bytes_dinamico(tamanho_bytes)
            bytes_str = f"{tamanho_bytes:,}".replace(",", ".")

            if tipo_unidade == 5:
                # Tratamento especial forense para mídias ópticas
                str_capacidade = f"{tamanho_dinamico} ({bytes_str} bytes) [Nota: Em mídias ópticas, este é o tamanho da sessão gravada, não a capacidade física do disco]"
            else:
                str_capacidade = f"{tamanho_dinamico} ({bytes_str} bytes)"
        else:
            str_capacidade = "[Indisponível - Mídia vazia, corrompida ou formato inacessível pelo Windows]"

        # 3. Monta o dicionário de retorno
        if sucesso:
            # Formata o serial no padrão clássico hexadecimal do Windows (XXXX-XXXX)
            serial_hex = f"{serial_number.value:08X}"
            serial_formatado = f"{serial_hex[:4]}-{serial_hex[4:]}"

            return {
                'unidade': drive,
                'rotulo': volume_name_buffer.value or "[Sem Rótulo]",
                'serial': serial_formatado,
                'sistema_arquivos': file_system_name_buffer.value,
                'capacidade': str_capacidade
            }
    except Exception:
        pass
    return None


def _reunir_hashes_quebrados_pdf(texto: str) -> str:
    # 1. Limpa caracteres invisíveis que o extrator de PDF injeta secretamente
    texto = re.sub(r'[\u200b\u200e\u200f\x00]', '', texto)

    pos = 0
    while True:
        # Varre o documento procurando estritamente por PARES de hexadecimais contíguos
        # a partir do ponteiro de posição atual 'pos'
        match = re.search(r'([a-fA-F0-9]{10,})[\s\n\r]+([a-fA-F0-9]{10,})', texto[pos:])
        if not match:
            break

        p1 = match.group(1)
        p2 = match.group(2)
        combinado = p1 + p2

        # Se a soma dos dois pedaços resultar em um tamanho criptográfico padrão válido
        if len(combinado) in {32, 40, 64, 96, 128}:
            start_idx = pos + match.start()
            end_idx = pos + match.end()
            # Funde o hash quebrado eliminando a quebra de linha interna
            texto = texto[:start_idx] + combinado + texto[end_idx:]
            # Reseta o ponteiro para o início para garantir que quebras múltiplas encadeadas se resolvam
            pos = 0
        else:
            # Caso o par encontrado não seja um hash partido (ex: um SHA-1 legítimo seguido de um SHA-256),
            # movemos o ponteiro para frente ignorando o primeiro elemento para evitar loops infinitos.
            pos += match.start() + len(p1)

    return texto


class TextEditCustodia(QTextEdit):
    """Caixa de texto customizada que aceita arquivos PDF/DOCX/XLSX/TXT via Drag & Drop."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

        self.nome_arquivo_origem = None
        self.hash_arquivo_origem = None

        # Mensagem visual em HTML adaptada para dimensões menores
        self._texto_fundo = """
        <div style="text-align: center; color: #888888; font-family: sans-serif;">
            <span style="font-size: 12pt; font-weight: bold; color: #0078D7;">VALIDAR CADEIA DE CUSTÓDIA (opcional)</span><br><br>
            <span style="font-size: 9.5pt; line-height: 140%;">
                <b>Arraste e solte AQUI</b> o relatório de hashes encaminhados pela origem (ex. delegacia) em formato <i>PDF, DOCX, XLSX ou TXT</i><br>
                ou <b>copie e cole o texto</b> ou <b>digite</b> livremente neste mesmo espaço para realizar a validação automática da cadeia de custódia.<br>
                <span style="font-size: 8.5pt; color: #a0a0a0;">(Nota: Hashes CRC32 são desconsiderados nesta verificação)</span>
            </span>
        </div>
        """

    def paintEvent(self, event):
        """Sobrescreve a pintura para renderizar o HTML de fundo quando o campo estiver vazio."""
        super().paintEvent(event)

        if not self.toPlainText():
            from PySide6.QtGui import QPainter, QTextDocument
            from PySide6.QtCore import Qt

            painter = QPainter(self.viewport())

            # Utiliza o QTextDocument para interpretar e renderizar as tags HTML
            doc = QTextDocument()
            doc.setHtml(self._texto_fundo)

            # Ajusta a largura do documento para que a quebra de linha respeite as bordas do campo
            largura_util = self.viewport().width() - 20
            doc.setTextWidth(largura_util)

            # Cálculos para centralizar o bloco HTML verticalmente com segurança
            altura_texto = doc.size().height()
            altura_campo = self.viewport().height()
            y_offset = max(10, int((altura_campo - altura_texto) / 2))

            painter.save()
            painter.translate(10, y_offset)
            doc.drawContents(painter)
            painter.restore()

    def validar_arrasto(self, event):
        """função auxiliar para checar se o item arrastado é válido."""
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()

            # Regra 1: Deve ser estritamente UM único item
            if len(urls) == 1:
                caminho = urls[0].toLocalFile()

                # Regra 2: Deve ser um arquivo (bloqueia diretórios e unidades lógicas)
                if os.path.isfile(caminho):
                    return True
        return False

    def dragEnterEvent(self, event):
        if self.validar_arrasto(event):
            # Salva o estilo atual de forma dinâmica (suporta o Modo Escuro/Claro)
            self._estilo_anterior = self.styleSheet()
            # Aplica o feedback visual: Borda verde tracejada indicando validação
            self.setStyleSheet(
                self._estilo_anterior + " border: 2px dashed #28a745; background-color: rgba(40, 167, 69, 0.05);")

            event.acceptProposedAction()
        else:
            # Muda a ação para ignorar (🚫) e aceita o evento para não repassar ao pai
            event.setDropAction(Qt.DropAction.IgnoreAction)
            event.accept()

    def dragMoveEvent(self, event):
        if self.validar_arrasto(event):
            event.acceptProposedAction()
        else:
            # Mantém o cursor de proibido (🚫) enquanto o mouse se move por cima
            event.setDropAction(Qt.DropAction.IgnoreAction)
            event.accept()

    def dragLeaveEvent(self, event):
        # Restaura o estilo original se o usuário tirar o mouse de cima (desistir de soltar)
        if hasattr(self, '_estilo_anterior'):
            self.setStyleSheet(self._estilo_anterior)
        super().dragLeaveEvent(event)

    def dropEvent(self, event):
        # Restaura o estilo original logo após o usuário soltar o arquivo
        if hasattr(self, '_estilo_anterior'):
            self.setStyleSheet(self._estilo_anterior)

        if self.validar_arrasto(event):
            urls = event.mimeData().urls()
            caminho_arquivo = urls[0].toLocalFile()
            event.acceptProposedAction()
            self.carregar_arquivo(caminho_arquivo)
        else:
            event.setDropAction(Qt.DropAction.IgnoreAction)
            event.accept()

            # Fallback amigável caso o sistema operacional force a soltura
            if event.mimeData().hasUrls():
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.warning(
                    self,
                    "Aviso Forense",
                    "A área de Cadeia de Custódia aceita apenas UM arquivo por vez.\n\nMúltiplos arquivos, diretórios ou unidades não são suportados neste campo. Por favor, arraste o arquivo do laudo isoladamente."
                )

    def carregar_arquivo(self, caminho):
        """Lê o arquivo arrastado e extrai o texto de forma nativa e segura."""
        self.nome_arquivo_origem = os.path.basename(caminho)

        # --- CÁLCULO DO HASH (SHA-256) DO ARQUIVO DE REFERÊNCIA ---
        try:
            import hashlib
            sha256_ref = hashlib.sha256()
            with open(caminho, 'rb') as f_hash:
                while chunk := f_hash.read(65536):
                    sha256_ref.update(chunk)
            self.hash_arquivo_origem = sha256_ref.hexdigest().upper()
        except Exception:
            self.hash_arquivo_origem = "[Erro ao calcular hash]"

        extensao = caminho.lower().split('.')[-1]
        texto_extraido = ""

        try:
            # 1. LEITURA DE PDF
            if extensao == 'pdf':
                reader = PdfReader(caminho)
                for page in reader.pages:
                    texto_pagina = page.extract_text()
                    if texto_pagina:
                        texto_extraido += texto_pagina + "\n"

                texto_extraido = _reunir_hashes_quebrados_pdf(texto_extraido)

                # Aviso de PDF Escaneado (Imagem)
                if not texto_extraido.strip():
                    texto_extraido = (
                        "⚠️ [AVISO FORENSE]\n"
                        "Nenhum texto digital detectado neste PDF.\n\n"
                        "O arquivo parece ser um documento escaneado (composto apenas por imagens). "
                        "Por favor, copie e cole os hashes do documento original manualmente aqui."
                    )

            # 2. LEITURA NATIVA DE WORD MODERNO (DOCX)
            elif extensao == 'docx':
                try:
                    with zipfile.ZipFile(caminho) as z:
                        xml_content = z.read('word/document.xml')
                        tree = ET.fromstring(xml_content)
                        textos = []
                        # Itera sobre os parágrafos para não quebrar palavras ao meio
                        for p_node in tree.iter():
                            if p_node.tag.endswith('}p'):
                                texto_paragrafo = ""
                                for t_node in p_node.iter():
                                    if t_node.tag.endswith('}t') and t_node.text:
                                        texto_paragrafo += t_node.text
                                if texto_paragrafo:
                                    textos.append(texto_paragrafo)
                        texto_extraido = "\n".join(textos)
                except zipfile.BadZipFile:
                    texto_extraido = "⚠️ Erro: O arquivo DOCX está corrompido."

            # 3. LEITURA NATIVA DE EXCEL MODERNO (XLSX)
            elif extensao == 'xlsx':
                try:
                    with zipfile.ZipFile(caminho) as z:
                        textos = []
                        # No Excel, os textos das células ficam salvos no sharedStrings.xml
                        if 'xl/sharedStrings.xml' in z.namelist():
                            xml_content = z.read('xl/sharedStrings.xml')
                            tree = ET.fromstring(xml_content)
                            for si_node in tree.iter():
                                if si_node.tag.endswith('}si'):
                                    texto_item = ""
                                    for t_node in si_node.iter():
                                        if t_node.tag.endswith('}t') and t_node.text:
                                            texto_item += t_node.text
                                    if texto_item:
                                        textos.append(texto_item)
                        texto_extraido = "\n".join(textos)
                except zipfile.BadZipFile:
                    texto_extraido = "⚠️ Erro: O arquivo XLSX está corrompido."

            # 4. AVISO PARA FORMATOS LEGADOS (DOC / XLS)
            elif extensao in ['doc', 'xls']:
                texto_extraido = (
                    f"⚠️ [FORMATO LEGADO NÃO SUPORTADO]\n"
                    f"O formato (.{extensao}) possui uma estrutura binária fechada.\n\n"
                    f"Para garantir a precisão da extração sem corromper os hashes, abra o arquivo no Office e "
                    f"copie/cole o texto aqui, ou salve-o como PDF e arraste novamente."
                )

            # 5. ARQUIVOS DE TEXTO COMUNS (TXT, CSV)
            else:
                codificacoes_para_tentar = ['utf-8', 'utf-16', 'cp1252', 'latin-1']
                texto_lido = False

                for codificacao in codificacoes_para_tentar:
                    try:
                        # Tenta ler estritamente com a codificação atual da lista
                        with open(caminho, 'r', encoding=codificacao) as f:
                            texto_extraido = f.read()
                        texto_lido = True
                        break  # Se leu sem erro, quebra o loop
                    except UnicodeDecodeError:
                        continue  # Se deu erro de conversão, vai para a próxima codificação

                # Se todas as tentativas falharem, faz a leitura forçada substituindo os erros
                if not texto_lido:
                    with open(caminho, 'r', encoding='utf-8', errors='replace') as f:
                        texto_extraido = f.read()

            self.setPlainText(texto_extraido)
            # Imprime no console (se aberto) que o carregamento foi bem sucedido
            print(f"Relatório carregado: {os.path.basename(caminho)}")
        except Exception as e:
            self.setPlainText(f"Erro inesperado ao ler o arquivo de referência: {str(e)}")

    def clear(self):
        """Sobrescreve a limpeza para esquecer o nome e o hash do arquivo quando o botão Limpar for clicado."""
        self.nome_arquivo_origem = None
        self.hash_arquivo_origem = None
        super().clear()


class ValidadorCustodia:
    """Implementa a validação por agrupamento de blocos de hashes sequenciais (Apartamentos Criptográficos)."""

    def __init__(self, texto_referencia: str, is_pdf: bool = False):
        # 🔥 PROTEÇÃO TOTAL: Executa a cura de hashes partidos diretamente na entrada do texto.
        # Isto garante que mesmo um Ctrl+V de um PDF limpe os caracteres invisíveis e junte o SHA-512.
        texto_curado = _reunir_hashes_quebrados_pdf(texto_referencia)

        self.linhas = [linha.strip() for linha in texto_curado.splitlines()]
        self.is_pdf = is_pdf

        # Padrões com 'word boundaries' para identificar tamanhos exatos de hashes hexadecimais
        self.padroes = {
            "MD5": r'\b[a-fA-F0-9]{32}\b',
            "SHA-1": r'\b[a-fA-F0-9]{40}\b',
            "SHA-256": r'\b[a-fA-F0-9]{64}\b',
            "SHA-384": r'\b[a-fA-F0-9]{96}\b',
            "SHA-512": r'\b[a-fA-F0-9]{128}\b'
        }

        self.blocos = []
        self._mapear_texto()

    def _mapear_texto(self):
        """Varre o texto linearmente e fecha o bloco atual sempre que qualquer algoritmo se repetir."""
        bloco_atual = {}

        for linha in self.linhas:
            if not linha:
                continue

            # Localiza os hashes mantendo a ordem de leitura horizontal (esquerda para a direita)
            hashes_linha = []
            for algo, padrao in self.padroes.items():
                for match in re.finditer(padrao, linha):
                    hashes_linha.append({
                        'algo': algo,
                        'valor': match.group().upper(),
                        'pos': match.start()
                    })

            # Ordena os tokens encontrados na mesma linha
            hashes_linha.sort(key=lambda x: x['pos'])

            for item in hashes_linha:
                algo = item['algo']
                valor = item['valor']

                # INTELEGÊNCIA CÍCLICA: se o algoritmo já existe no bloco, o ciclo mudou de arquivo.
                if algo in bloco_atual:
                    self.blocos.append(bloco_atual)
                    bloco_atual = {}

                bloco_atual[algo] = valor

        # Registra o último apartamento gerado caso não esteja vazio
        if bloco_atual:
            self.blocos.append(bloco_atual)

    def validar(self, caminho_arquivo: str, hashes_calculados: dict) -> tuple[int, str]:
        """Valida se TODOS os hashes calculados coexistem harmoniosamente dentro de um mesmo bloco."""
        nome_arquivo_atual = os.path.basename(caminho_arquivo)

        # Filtra o CRC32 do escopo da custódia para mitigar falsos positivos estruturais
        algos_para_validar = {algo: val for algo, val in hashes_calculados.items() if algo != "CRC32"}
        if not algos_para_validar:
            return 3, "❌ DIVERGÊNCIA - Nenhum algoritmo criptográfico forte disponível para validação de custódia."

        bloco_candidato = None
        algos_conferem = []
        algos_falharam = []

        # Localiza qual bloco "reivindica" a autoria deste arquivo (possui pelo menos um hash idêntico)
        for bloco in self.blocos:
            reivindicado = False
            for algo, val_calc in algos_para_validar.items():
                if algo in bloco and bloco[algo] == val_calc:
                    reivindicado = True
                    break

            if reivindicado:
                bloco_candidato = bloco
                # Uma vez achado o bloco correspondente, auditamos a integridade de TODOS os outros hashes nele
                for algo, val_calc in algos_para_validar.items():
                    if algo in bloco:
                        if bloco[algo] == val_calc:
                            algos_conferem.append(algo)
                        else:
                            algos_falharam.append(algo)
                break

        if bloco_candidato:
            # Sincroniza dados com o dicionário de resumo exigido pela GUI principal do programa
            if not hasattr(self, 'arquivos_validados_dict'):
                self.arquivos_validados_dict = {}
            if nome_arquivo_atual not in self.arquivos_validados_dict:
                self.arquivos_validados_dict[nome_arquivo_atual] = {}

            for a in algos_conferem:
                self.arquivos_validados_dict[nome_arquivo_atual][a] = algos_para_validar[a]

            # Se achou o bloco mas houve divergência interna entre os tipos de hashes (Vulnerabilidade Inversão)
            if algos_falharam:
                texto_conferem = ' e '.join(algos_conferem) if len(algos_conferem) < 3 else ', '.join(
                    algos_conferem[:-1]) + ' e ' + algos_conferem[-1]
                texto_falhos = ' e '.join(algos_falharam) if len(algos_falharam) < 3 else ', '.join(
                    algos_falharam[:-1]) + ' e ' + algos_falharam[-1]
                sufixo = 's' if len(algos_conferem) > 1 else ''
                return 4, f"⚠️ ALERTA PARCIAL - {texto_conferem} validado{sufixo}, mas houve DIVERGÊNCIA no {texto_falhos} dentro do mesmo bloco de custódia."

            texto_algos = ' e '.join(algos_conferem) if len(algos_conferem) < 3 else ', '.join(
                algos_conferem[:-1]) + ' e ' + algos_conferem[-1]
            sufixo = 's' if len(algos_conferem) > 1 else ''
            return 1, f"✅ CONFERE - {texto_algos} validado{sufixo}."

        return 3, "❌ DIVERGÊNCIA - Nenhum hash calculado para este arquivo consta na relação original da Cadeia de Custódia."

    def validar_hash_simples(self, hashes_calculados: dict) -> tuple[int, str]:
        """Aplica a mesma regra de integridade de blocos para mídias em processamento RAW."""
        algos_para_validar = {algo: val for algo, val in hashes_calculados.items() if algo != "CRC32"}
        if not algos_para_validar:
            return 3, "❌ NÃO CONFERE - Nenhum algoritmo criptográfico forte disponível para validação da unidade."

        bloco_candidato = None
        algos_conferem = []
        algos_falharam = []

        for bloco in self.blocos:
            reivindicado = False
            for algo, val_calc in algos_para_validar.items():
                if algo in bloco and bloco[algo] == val_calc:
                    reivindicado = True
                    break

            if reivindicado:
                bloco_candidato = bloco
                for algo, val_calc in algos_para_validar.items():
                    if algo in bloco:
                        if bloco[algo] == val_calc:
                            algos_conferem.append(algo)
                        else:
                            algos_falharam.append(algo)
                break

        if bloco_candidato:
            texto_algos = " e ".join(algos_conferem) if len(algos_conferem) < 3 else ", ".join(
                algos_conferem[:-1]) + " e " + algos_conferem[-1]
            sufixo = "s" if len(algos_conferem) > 1 else ""

            if algos_falharam:
                texto_falhos = " e ".join(algos_falharam) if len(algos_falharam) < 3 else ", ".join(
                    algos_falharam[:-1]) + " e " + algos_falharam[-1]
                return 2, f"⚠️ ALERTA PARCIAL - Hash{sufixo} confere ({texto_algos}), mas houve DIVERGÊNCIA no {texto_falhos} dentro do mesmo bloco de custódia."

            return 1, f"✅ CONFERE - Hash{sufixo} ({texto_algos}) localizado{sufixo} no documento de custódia."

        return 3, "❌ NÃO CONFERE / NENHUM HASH DA UNIDADE LOCALIZADO NO TEXTO"

    def obter_lista_limpa(self) -> list:
        """Estrutura os apartamentos criptográficos detectados de forma clara no log final da tela."""
        lista_limpa = []
        for idx, bloco in enumerate(self.blocos):
            hashes_str = " | ".join([f"{algo}: {val}" for algo, val in bloco.items()])
            lista_limpa.append(f"📦 Bloco #{idx + 1}   |   {hashes_str}")
        return lista_limpa


class WorkerExtracao(QThread):
    sig_texto_append = Signal(str)
    sig_progresso_arquivo = Signal(object)
    sig_progresso_total = Signal(object)
    sig_lbl_arquivo = Signal(str)
    sig_lbl_total = Signal(str)
    sig_sync_bytes = Signal(object)
    sig_apagar_ultima_linha = Signal()
    sig_perguntar_nuvem = Signal(dict)
    sig_conclusao = Signal(dict)

    def __init__(self, lista_arquivos, info_drive, texto_custodia, veio_de_pdf, algos_selecionados, extrair_meta,
                 extrair_raw, janela):
        super().__init__()
        self.lista_arquivos = lista_arquivos
        self.info_drive = info_drive
        self.texto_custodia = texto_custodia
        self.veio_de_pdf = veio_de_pdf
        self.algos_selecionados = algos_selecionados
        self.extrair_meta = extrair_meta
        self.extrair_raw = extrair_raw
        self.janela = janela  # Referência segura, pois os métodos chamados não tocam na GUI

        self.cancelar_operacao = False
        self.ignorar_google_drive = None
        self.ignorar_nuvem_nativa = None

        self.nuvem_resposta = None
        self.nuvem_event = threading.Event()

        self.bytes_processados_total = 0
        self.arquivos_processados_qtd = 0
        self.contagem_extensoes = {}
        self.arquivos_por_hash = {}
        self.coordenadas_gps_encontradas = []
        self._hashes_com_gps = set()

    # noinspection PyTypeChecker
    def _obter_metadados_e_hashes_worker(self, caminho_arquivo, algos_selecionados, extrair_metadados=False) -> dict[str, Any]:
        try:
            stat_info = os.lstat(caminho_arquivo)
            if os.name == 'nt':
                # 1. BLOQUEIO NUVEM MICROSOFT
                if hasattr(stat_info, 'st_file_attributes'):
                    atributos = stat_info.st_file_attributes
                    if (atributos & 0x400000) or (atributos & 0x1000) or (atributos & 0x100000) or (
                            atributos & 0x40000):
                        if self.ignorar_nuvem_nativa is False:
                            return {'sucesso': False,
                                    'erro': 'ARQUIVO EM NUVEM DETECTADO: Proteção mantida pelo perito.'}
                        elif self.ignorar_nuvem_nativa is None:
                            payload = {
                                "titulo": "Aviso Forense - Atributos de Nuvem",
                                "texto": "<b>Foi detectado um arquivo com atributos de 'Nuvem / Apenas Online'.</b>",
                                "info": "O Windows informou que este arquivo pertence a um serviço de nuvem (OneDrive, Dropbox, etc.).\n\nVocê garante que o arquivo é local e deseja ignorar essa proteção para forçar a extração deste e de TODOS os demais arquivos na mesma situação neste lote?"
                            }
                            self.sig_perguntar_nuvem.emit(payload)
                            self.nuvem_event.wait()  # Trava a Thread até o usuário responder na GUI
                            self.ignorar_nuvem_nativa = self.nuvem_resposta
                            self.nuvem_event.clear()
                            if not self.ignorar_nuvem_nativa:
                                return {'sucesso': False,
                                        'erro': 'ARQUIVO EM NUVEM DETECTADO: Proteção mantida pelo perito.'}

                # 2. BLOQUEIO GOOGLE DRIVE
                try:
                    drive = os.path.splitdrive(caminho_arquivo)[0] + "\\"
                    if len(drive) >= 3:
                        info_vol = obter_info_volume(drive)
                        if info_vol:
                            rotulo = info_vol.get('rotulo', '').lower()
                            fs = info_vol.get('sistema_arquivos', '').upper()
                            if 'google drive' in rotulo or 'cbfs' in fs:
                                if self.ignorar_google_drive is False:
                                    return {'sucesso': False,
                                            'erro': f'DISCO VIRTUAL EM NUVEM DETECTADO ({rotulo.upper()}): Leitura bloqueada.'}
                                elif self.ignorar_google_drive is None:
                                    payload = {
                                        "titulo": "Risco Forense - Google Drive Detectado",
                                        "texto": "<b>Foi detectada uma origem de disco virtual do Google Drive.</b>",
                                        "info": "Como Perito, deseja ignorar a proteção de nuvem e extrair os hashes assim mesmo (assumindo o risco de download da internet)?"
                                    }
                                    self.sig_perguntar_nuvem.emit(payload)
                                    self.nuvem_event.wait()
                                    self.ignorar_google_drive = self.nuvem_resposta
                                    self.nuvem_event.clear()
                                    if not self.ignorar_google_drive:
                                        return {'sucesso': False,
                                                'erro': f'DISCO VIRTUAL EM NUVEM DETECTADO ({rotulo.upper()}): Leitura bloqueada.'}
                except Exception:
                    pass

            tamanho_bytes = stat_info.st_size
            tamanho_mb = tamanho_bytes / (1024 * 1024)
            data_modificacao = datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime('%d/%m/%Y %H:%M:%S')

            objetos_hash = {}
            if "CRC32" in algos_selecionados: objetos_hash["CRC32"] = 0
            if "MD5" in algos_selecionados: objetos_hash["MD5"] = hashlib.md5()
            if "SHA-1" in algos_selecionados: objetos_hash["SHA-1"] = hashlib.sha1()
            if "SHA-256" in algos_selecionados: objetos_hash["SHA-256"] = hashlib.sha256()
            if "SHA-384" in algos_selecionados: objetos_hash["SHA-384"] = hashlib.sha384()
            if "SHA-512" in algos_selecionados: objetos_hash["SHA-512"] = hashlib.sha512()

            contagem_bytes = Counter() if extrair_metadados else None

            self.sig_progresso_arquivo.emit(0)
            bytes_processados = 0
            tamanho_chunk = 65536

            try:
                with open(caminho_arquivo, 'rb') as f:
                    if os.name == 'nt' and tamanho_bytes > 0:
                        try:
                            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                        except OSError:
                            return {'sucesso': False, 'erro': 'ARQUIVO EM USO: Modificação ativa detectada.'}
                    try:
                        while True:
                            chunk = f.read(tamanho_chunk)
                            if not chunk: break
                            if self.cancelar_operacao:
                                return {'sucesso': False, 'erro': 'OPERAÇÃO CANCELADA PELO USUÁRIO'}

                            for algo in algos_selecionados:
                                if algo == "CRC32":
                                    objetos_hash["CRC32"] = zlib.crc32(chunk, objetos_hash["CRC32"])
                                else:
                                    objetos_hash[algo].update(chunk)

                            if extrair_metadados:
                                contagem_bytes.update(chunk)

                            bytes_processados += len(chunk)
                            self.bytes_processados_total += len(chunk)

                            if bytes_processados % (tamanho_chunk * 16) == 0:
                                percentual = int(
                                    (bytes_processados / tamanho_bytes) * 100) if tamanho_bytes > 0 else 100
                                self.sig_progresso_arquivo.emit(percentual)
                                self.sig_sync_bytes.emit(
                                    self.bytes_processados_total)  # Sincroniza a barra ETA da tela principal
                    finally:
                        if os.name == 'nt' and tamanho_bytes > 0:
                            try:
                                f.seek(0)
                                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                            except Exception:
                                pass
            except PermissionError:
                return {'sucesso': False,
                        'erro': 'ACESSO NEGADO / ARQUIVO EM USO (Sistema Operacional bloqueou a leitura).'}
            except OSError as e:
                return {'sucesso': False,
                        'erro': f'ERRO DE DISCO/CORRUPÇÃO/TIMEOUT (Código {e.errno}): Falha na controladora ou Hardware.'}
            except Exception as e:
                return {'sucesso': False, 'erro': repr(e)}

            self.sig_progresso_arquivo.emit(100)

            resultado_entropia = None
            if extrair_metadados:
                entropia = 0.0
                if tamanho_bytes > 0:
                    for contagem in contagem_bytes.values():
                        probabilidade = contagem / tamanho_bytes
                        entropia -= probabilidade * math.log2(probabilidade)

                _, ext_arquivo = os.path.splitext(caminho_arquivo)
                ext_arquivo = ext_arquivo.lower().replace('.', '')
                formatos_comprimidos = ['jpg', 'jpeg', 'png', 'webp', 'gif', 'zip', 'rar', '7z', 'gz', 'mp4', 'mkv',
                                        'avi', 'mp3', 'm4a', 'pdf']

                status_entropia = ""
                if entropia > 7.9:
                    status_entropia = " (Normal para o formato comprimido deste arquivo)" if ext_arquivo in formatos_comprimidos else " (⚠️ ALERTA: Alta entropia - Possível Criptografia / Arquivo Packed)"
                elif entropia < 1.0:
                    status_entropia = " (Baixa entropia - Arquivo altamente repetitivo ou vazio)"
                else:
                    status_entropia = " (Entropia normal - Sem indícios de ofuscação ou criptografia)"
                resultado_entropia = f"{entropia:.4f}{status_entropia}"

            resultados_hash = {}
            for algo in algos_selecionados:
                if algo == "CRC32":
                    resultados_hash["CRC32"] = f"{objetos_hash['CRC32'] & 0xFFFFFFFF:08X}"
                else:
                    resultados_hash[algo] = objetos_hash[algo].hexdigest().upper()

            hashes_arquivo_vazio = {"CRC32": "00000000", "MD5": "D41D8CD98F00B204E9800998ECF8427E",
                                    "SHA-256": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"}
            arquivo_vazio_detectado = any(
                alg in resultados_hash and resultados_hash[alg] == h for alg, h in hashes_arquivo_vazio.items())

            return {'sucesso': True, 'hashes': resultados_hash, 'bytes': tamanho_bytes, 'mb': tamanho_mb,
                    'data': data_modificacao, 'entropia': resultado_entropia, 'arquivo_vazio': arquivo_vazio_detectado}
        except Exception as e:
            return {'sucesso': False, 'erro': repr(e)}

    def run(self):
        total_arquivos = len(self.lista_arquivos)
        validador = None
        qtd_validados = qtd_nao_validados = qtd_alertas_parciais = 0

        if self.texto_custodia:
            validador = ValidadorCustodia(self.texto_custodia, is_pdf=self.veio_de_pdf)

        if self.info_drive:
            self.sig_texto_append.emit("💿 INFORMAÇÕES DA UNIDADE DE ORIGEM (Extração de Unidade Lógica):")
            self.sig_texto_append.emit(f" ↳ Letra: {self.info_drive.get('unidade', 'N/A')}")
            self.sig_texto_append.emit(f" ↳ Rótulo (Label): {self.info_drive.get('rotulo', '[Sem Rótulo]')}")
            self.sig_texto_append.emit(
                f" ↳ Serial do Volume (Lógico): {self.info_drive.get('serial', 'Não detectado')}")
            self.sig_texto_append.emit(f" ↳ Formato (FS): {self.info_drive.get('sistema_arquivos', 'Desconhecido')}")
            self.sig_texto_append.emit(
                f" ↳ Capacidade Total: {self.info_drive.get('capacidade', 'Não identificada')}\n")

            letra_limpa = self.info_drive['unidade']
            # Supre o bloco de hardware se a unidade for uma mídia óptica (CD/DVD)
            if get_drive_type(letra_limpa) != DRIVE_CDROM:
                hw_info = obter_info_hardware_por_letra(letra_limpa)
                self.sig_texto_append.emit("⚙️  INFORMAÇÕES DE HARDWARE FÍSICO (Device Information):")
                self.sig_texto_append.emit(f" ↳ Tipo de Conexão (Bus Type): {hw_info['bus_type']}")
                self.sig_texto_append.emit(f" ↳ Dispositivo (Fabricante/Modelo): {hw_info['modelo_fabricante']}")
                self.sig_texto_append.emit(f" ↳ Serial de Fábrica (Hardware): {hw_info['serial']}")

                # Validação: Sempre exibe a nota técnica se o barramento físico for USB
                if "USB" in str(hw_info.get('bus_type', '')).upper():
                    self.sig_texto_append.emit(
                        "   ↳ Nota: Caso a mídia analisada (como um cartão SD/MicroSD) esteja conectada através de um adaptador ou leitor USB, o número de série exibido acima pode pertencer ao próprio adaptador e não à unidade física de armazenamento.")
                self.sig_texto_append.emit("\n")

        self.sig_texto_append.emit("-" * 60 + "\n")

        for indice, arquivo in enumerate(self.lista_arquivos):
            if self.cancelar_operacao:
                self.sig_texto_append.emit("\n[!] PROCESSO INTERROMPIDO PELO USUÁRIO.\n")
                self.sig_lbl_arquivo.emit("Progresso do Arquivo Atual: Cancelado")
                break

            nome_arquivo = os.path.basename(arquivo)
            self.sig_lbl_arquivo.emit(f"Progresso do Arquivo Atual: {nome_arquivo}")
            self.sig_texto_append.emit(f"===== ARQUIVO #{indice + 1}/{total_arquivos} =====")
            self.sig_texto_append.emit(f"Arquivo: {arquivo}")

            resultado = self._obter_metadados_e_hashes_worker(arquivo, self.algos_selecionados,
                                                              extrair_metadados=(self.extrair_meta or self.extrair_raw))

            if resultado['sucesso']:
                self.arquivos_processados_qtd += 1
                _, extensao = os.path.splitext(arquivo)
                extensao = extensao.upper()[1:] if extensao else "SEM EXTENSÃO"
                self.contagem_extensoes[extensao] = self.contagem_extensoes.get(extensao, 0) + 1

                hashes_calculados = resultado.get('hashes', {})
                chave_agrupamento = tuple(sorted((k, v) for k, v in hashes_calculados.items() if k != "CRC32"))
                if not chave_agrupamento:
                    chave_agrupamento = tuple(sorted(hashes_calculados.items()))

                if chave_agrupamento not in self.arquivos_por_hash:
                    self.arquivos_por_hash[chave_agrupamento] = []
                self.arquivos_por_hash[chave_agrupamento].append(arquivo)

                self.sig_texto_append.emit(f"Tamanho: {resultado['bytes']} bytes ({resultado['mb']:.2f} MB)")
                self.sig_texto_append.emit(f"Modificado em: {resultado['data']}")

                for algo in self.algos_selecionados:
                    hash_val = resultado.get('hashes', {}).get(algo, "Indisponível")
                    self.sig_texto_append.emit(f"{algo}: {hash_val}")

                self.sig_texto_append.emit("")

                if resultado.get('entropia'):
                    self.sig_texto_append.emit(f"Entropia (Shannon): {resultado['entropia']}")

                if resultado.get('arquivo_vazio', False):
                    self.sig_texto_append.emit(
                        "ℹ️ ARQUIVO VAZIO: Hash universalmente conhecido (0 bytes - Criado pelo sistema mas nunca utilizado)")

                if self.extrair_meta or self.extrair_raw:
                    if self.extrair_raw:
                        self.sig_texto_append.emit(
                            "⏳ AVISO: Renderizando Raw Dump massivo... A interface pode pausar por alguns instantes...")

                    # Chamada 100% segura, a lógica dele roda na Thread e não altera a GUI
                    metadados_midia = self.janela.obter_metadados_avancados(arquivo, extrair_raw=self.extrair_raw)

                    if self.extrair_raw:
                        self.sig_apagar_ultima_linha.emit()

                    if metadados_midia:
                        self.sig_texto_append.emit("\n".join(metadados_midia))

                        for linha in metadados_midia:
                            match = re.search(r"📍 GPS \(Latitude, Longitude\):\s*(-?\d+\.\d+),\s*(-?\d+\.\d+)", linha)
                            if match:
                                lat, lon = match.groups()
                                tem_hash_forte = any(algo != "CRC32" for algo in self.algos_selecionados)
                                if not tem_hash_forte:
                                    self.coordenadas_gps_encontradas.append((arquivo, lat, lon))
                                else:
                                    chave_coordenada = (chave_agrupamento, lat, lon)
                                    if chave_coordenada not in self._hashes_com_gps:
                                        self.coordenadas_gps_encontradas.append((arquivo, lat, lon))
                                        self._hashes_com_gps.add(chave_coordenada)

                if validador:
                    status, msg_custodia = validador.validar(arquivo, hashes_calculados)
                    self.sig_texto_append.emit("")
                    self.sig_texto_append.emit(msg_custodia)

                    if status == 1:
                        qtd_validados += 1
                    elif status == 4:
                        qtd_alertas_parciais += 1
                    else:
                        qtd_nao_validados += 1

            else:
                self.sig_texto_append.emit(f"Erro: {resultado['erro']}")

            self.sig_texto_append.emit("-" * 60 + "\n")
            self.sig_progresso_total.emit(indice + 1)

        payload_final = {
            "cancelar_operacao": self.cancelar_operacao,
            "contagem_extensoes": self.contagem_extensoes,
            "arquivos_processados_qtd": self.arquivos_processados_qtd,
            "arquivos_por_hash": self.arquivos_por_hash,
            "qtd_validados": qtd_validados,
            "qtd_alertas_parciais": qtd_alertas_parciais,
            "qtd_nao_validados": qtd_nao_validados,
            "lista_referencia": validador.obter_lista_limpa() if validador else None,
            "coordenadas_gps_encontradas": self.coordenadas_gps_encontradas
        }
        self.sig_conclusao.emit(payload_final)


class JanelaHashes(QWidget):
    sinal_atualizacao = Signal(str, str, str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{NOME_APP} - v.{VERSAO_APP}")
        self.resize(900, 730)

        if os.path.exists(ICON_PATH):
            self.setWindowIcon(QIcon(ICON_PATH))

        self.setAcceptDrops(True)
        self.cancelar_operacao = False
        self.processando = False

        self.setup_ui()

        # --- LIMPEZA PREVENTIVA DE RASTROS DE EXECUÇÕES ANTERIORES ---
        self.limpar_arquivos_temporarios()

        # --- CONTROLE DE TEMPO DECORRIDO E DE TEMPO RESTANTE ---
        self.timer_tempo = QTimer(self)
        self.timer_tempo.timeout.connect(self.atualizar_tempo_total)
        self.bytes_processados_total = 0
        self.total_bytes_processar = 0
        self.tempo_inicio_total = 0

        self.video_teve_fps_min_max = False
        self.video_teve_fps_geral = False

        # Conecta o sinal emitido pela thread à função que altera a interface
        self.sinal_atualizacao.connect(self._exibir_alerta_atualizacao)
        # --- CHAMA A ROTINA DE CHECAGEM DE NOVA ATUALIZAÇÃO DE VERSÃO ---
        self.checar_atualizacoes()

    def setup_ui(self):
        # Layout raiz da janela inteira
        layout_raiz = QVBoxLayout(self)
        layout_raiz.setContentsMargins(0, 0, 0, 0)  # Remove margens globais para maximizar espaço

        # Opcional: Um botão de teste fixo no topo para você alternar os visuais durante o desenvolvimento
        self.btn_alternar_visual = QPushButton("Alternar para Visual Moderno (Foco em Drag & Drop)")
        self.btn_alternar_visual.setStyleSheet(
            "background-color: #0078D7; color: white; font-weight: bold; padding: 5px;")
        self.btn_alternar_visual.clicked.connect(self.alternar_visual)
        layout_raiz.addWidget(self.btn_alternar_visual)

        # Cria o "Baralho" de telas
        self.stacked_widget = QStackedWidget()
        layout_raiz.addWidget(self.stacked_widget)

        # ---------------------------------------------------------
        # TELA 0: VISUAL CLÁSSICO
        # ---------------------------------------------------------
        self.container_classico = QWidget()
        self.setup_ui_classico(self.container_classico)
        self.stacked_widget.addWidget(self.container_classico)

        # ---------------------------------------------------------
        # TELA 1: VISUAL NOVO
        # ---------------------------------------------------------
        self.container_moderno = QWidget()
        self.setup_ui_moderno(self.container_moderno)
        self.stacked_widget.addWidget(self.container_moderno)

        # Define qual tela aparece primeiro ao abrir o app
        self.stacked_widget.setCurrentIndex(0)

    def setup_ui_classico(self, parent_widget):
        # A única alteração na sua lógica original é passar o parent_widget aqui:
        layout_principal = QVBoxLayout(parent_widget)
        layout_principal.setContentsMargins(10, 10, 10, 10)

        # ==============================================================
        # --- BLOCO 0: Linha Superior (Write-Blocker + Utilidades) ---
        # ==============================================================
        layout_linha_superior = QHBoxLayout()

        # 1. CAIXA DO WRITE-BLOCKER (Esquerda)
        self.grupo_wb = QGroupBox("Proteção Forense (Write-Blocker)")
        self.grupo_wb.setStyleSheet("""
                            QGroupBox { border: 1px solid #cccccc; margin-top: 10px; border-radius: 3px; padding-top: 5px; }
                            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; color: #111111; }
                        """)
        layout_wb = QHBoxLayout()

        self.btn_write_blocker = QPushButton("BLOQUEAR ESCRITA EM USB")
        self.btn_write_blocker.setMinimumHeight(28)
        self.btn_write_blocker.setMinimumWidth(240)
        self.btn_write_blocker.clicked.connect(self.alternar_write_blocker)
        layout_wb.addWidget(self.btn_write_blocker)
        self.grupo_wb.setLayout(layout_wb)

        layout_linha_superior.addWidget(self.grupo_wb)

        # 2. CAIXA DE CONFIGURAÇÕES E UTILIDADES (Direita)
        self.grupo_topo = QGroupBox("Configurações e Utilidades")
        self.grupo_topo.setStyleSheet("""
                            QGroupBox { border: 1px solid #cccccc; margin-top: 10px; border-radius: 3px; padding-top: 5px; }
                            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; color: #111111; }
                        """)
        layout_opcoes_topo = QHBoxLayout()

        self.btn_formatos = QPushButton("Formatos Suportados")
        self.btn_formatos.setMinimumWidth(150)
        self.btn_formatos.setMinimumHeight(28)
        self.btn_formatos.clicked.connect(self.mostrar_formatos)
        layout_opcoes_topo.addWidget(self.btn_formatos)

        self.btn_manual_online = QPushButton("Manual Online")
        self.btn_manual_online.setMinimumWidth(120)
        self.btn_manual_online.setMinimumHeight(28)
        self.btn_manual_online.setToolTip("Guia de Operação e Instruções.")
        self.btn_manual_online.clicked.connect(self.abrir_manual_online)
        layout_opcoes_topo.addWidget(self.btn_manual_online)

        self.btn_sobre = QPushButton("Sobre")
        self.btn_sobre.setMinimumWidth(90)
        self.btn_sobre.setMinimumHeight(28)
        self.btn_sobre.clicked.connect(self.mostrar_sobre)
        layout_opcoes_topo.addWidget(self.btn_sobre)

        layout_opcoes_topo.addStretch()

        self.chk_modo_escuro = QCheckBox("🌙 Modo Escuro")
        self.chk_modo_escuro.setStyleSheet("font-weight: bold; padding: 2px;")
        self.chk_modo_escuro.toggled.connect(self.alternar_modo_escuro)
        layout_opcoes_topo.addWidget(self.chk_modo_escuro)

        self.grupo_topo.setLayout(layout_opcoes_topo)
        layout_linha_superior.addWidget(self.grupo_topo)

        # Adiciona a linha superior combinada à janela
        layout_principal.addLayout(layout_linha_superior)

        # ==============================================================
        # --- BLOCO 1: Caixa de Operações Forenses (Controles + Hashes) ---
        # ==============================================================
        self.grupo_controles = QGroupBox("Controles de Extração de Evidências")
        # Força o alinhamento e o padding idênticos desde o primeiro milissegundo de criação
        self.grupo_controles.setStyleSheet("""
                    QGroupBox { border: 1px solid #cccccc; margin-top: 10px; border-radius: 3px; padding-top: 5px; }
                    QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; color: #111111; }
                """)
        layout_grupo_controles = QVBoxLayout()

        # --- Sub-linha A: Botões de Origem ---
        layout_botoes_origem = QHBoxLayout()

        self.btn_arquivo = QPushButton("Selecionar Arquivo(s)")
        self.btn_arquivo.clicked.connect(self.selecionar_arquivo)
        layout_botoes_origem.addWidget(self.btn_arquivo)

        self.btn_diretorio = QPushButton("Selecionar Diretório")
        self.btn_diretorio.clicked.connect(self.selecionar_diretorio)
        layout_botoes_origem.addWidget(self.btn_diretorio)

        self.chk_subdiretorios = QCheckBox("Incluir Subdiretórios")
        self.chk_subdiretorios.setChecked(True)
        layout_botoes_origem.addWidget(self.chk_subdiretorios)

        layout_botoes_origem.addSpacing(25)

        self.btn_unidade_raw = QPushButton("Selecionar Unidade (RAW)")
        self.btn_unidade_raw.setToolTip(
            "<p><b>Aquisição Forense e Hash RAW (Bit-a-Bit)</b></p>"
            "<p>Realiza a extração de baixo nível (setor por setor) de mídias físicas ou lógicas (HDs, SSDs, Pendrives, CDs e DVDs).</p>"
            "<ul>"
            "<li>Gera um <b>HASH único</b> que atesta matematicamente o estado integral da evidência.</li>"
            "<li>Permite salvar uma cópia idêntica através de <b>Imagem Forense (.E01 ou .dd)</b>.</li>"
            "</ul>"
        )
        self.btn_unidade_raw.clicked.connect(self.selecionar_unidade_raw)
        self.btn_unidade_raw.installEventFilter(self)
        self.btn_unidade_raw.setStyleSheet("""
                            QPushButton {
                                font-weight: bold; 
                                color: #800000; 
                                background-color: #e6e6e6;
                                border: 1px solid #cccccc;
                                border-radius: 4px;
                                padding: 4px;
                            }
                            QPushButton:hover { background-color: #d4d4d4; border: 1px solid #b3b3b3; }
                            QPushButton:pressed { background-color: #c5c5c5; border: 1px solid #999999; }
                            QPushButton:disabled { color: #999999; background-color: #f0f0f0; border: 1px solid #cccccc; }
                        """)
        layout_botoes_origem.addWidget(self.btn_unidade_raw)

        # Adiciona a primeira linha dentro da caixa
        layout_grupo_controles.addLayout(layout_botoes_origem)

        # --- Sub-linha B: Algoritmos e Metadados ---
        layout_hashes = QHBoxLayout()
        layout_hashes.addWidget(QLabel("Algoritmos:"))

        self.chk_hashes = {}
        lista_algoritmos = ["CRC32", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]

        tooltips_hashes = {
            "CRC32": "<p><b>CRC32:</b> Verificação de redundância (Não Criptográfico).</p>"
                     "<ul><li><b>Segurança:</b> Nula.</li>"
                     "<li><b>Colisão:</b> Altíssima.</li>"
                     "<li><b>Uso:</b> Inseguro para evidências. Útil apenas para detecção rápida de corrupção. <br><br>"
                     "<span style='color: #990000;'><b>⚠️ Nota Pericial:</b> Para evitar falsos positivos, o CRC32 é "
                     "intencionalmente ignorado na conferência automática da Cadeia de Custódia.</span></li></ul>",

            "MD5": "<p><b>MD5:</b> Hash criptográfico legado.</p>"
                   "<ul><li><b>Segurança:</b> Quebrada.</li>"
                   "<li><b>Colisão:</b> Muito Alta (facilmente forjada).</li>"
                   "<li><b>Uso:</b> Utilizado historicamente, mas hoje serve apenas para conferência de integridade simples, não para validação de evidência contra adulteração intencional.</li></ul>",

            "SHA-1": "<p><b>SHA-1:</b> Hash criptográfico obsoleto.</p>"
                     "<ul><li><b>Segurança:</b> Comprometida (Ataque SHAttered).</li>"
                     "<li><b>Colisão:</b> Comprovada na prática, mas exige vastos recursos computacionais e financeiros (ex: ataques de nível estatal).</li>"
                     "<li><b>Uso:</b> Ainda comum em sistemas antigos ou de versionamento (ex: Git), mas substituído pelo SHA-256 no meio pericial.</li></ul>",

            "SHA-256": "<p><b>SHA-256:</b> Padrão atual da indústria forense (Família SHA-2).</p>"
                       "<ul><li><b>Segurança:</b> Criptograficamente Seguro.</li>"
                       "<li><b>Colisão:</b> Praticamente Nula.</li>"
                       "<li><b>Uso:</b> Padrão-ouro aceito em tribunais internacionalmente para garantir a inalterabilidade da evidência.</li></ul>",

            "SHA-384": "<p><b>SHA-384:</b> Variação truncada do SHA-512 (Família SHA-2).</p>"
                       "<ul><li><b>Segurança:</b> Altamente Seguro (Imune a ataques de extensão de comprimento).</li>"
                       "<li><b>Colisão:</b> Nula.</li>"
                       "<li><b>Uso:</b> Exigido em níveis de segurança governamentais muito específicos.</li></ul>",

            "SHA-512": "<p><b>SHA-512:</b> Nível máximo da família SHA-2.</p>"
                       "<ul><li><b>Segurança:</b> Máxima (Nível Militar).</li>"
                       "<li><b>Colisão:</b> Nula.</li>"
                       "<li><b>Uso:</b> Perfeição criptográfica atual. <i>Dica: Geralmente calcula mais rápido que o SHA-256 em processadores modernos de 64-bits.</i></li></ul>"
        }

        for algo in lista_algoritmos:
            chk = QCheckBox(algo)
            if algo in ["SHA-256", "SHA-512"]:
                chk.setChecked(True)

            chk.setToolTip(tooltips_hashes[algo])
            chk.installEventFilter(self)

            layout_hashes.addWidget(chk)
            self.chk_hashes[algo] = chk

        layout_hashes.addSpacing(30)
        layout_hashes.addWidget(QLabel("Análise:"))

        layout_opcoes_metadados = QVBoxLayout()
        layout_opcoes_metadados.setSpacing(2)

        self.chk_metadados = QCheckBox("Incluir Metadados Básicos")
        self.chk_metadados.setChecked(True)
        self.chk_metadados.setToolTip(
            "<p><b>Suporte a extração de metadados avançados:</b></p>"
            "<ul>"
            "<li><b>Imagens (JPG, PNG, TIFF, WEBP...):</b> Resolução, Formato, DPI, Dispositivo (Marca/Modelo), Data de Captura, Software/Editor e Coordenadas GPS (com link para o Google Maps).</li>"
            "<li><b>Vídeos (MP4, AVI, MKV...):</b> Resolução, FPS, Duração, Data de Criação, Dispositivo de Gravação, Software e Coordenadas GPS (com link para o Google Maps).</li>"
            "<li><b>Documentos (PDF e Office):</b> Total de Páginas, Título Interno, Autor, Último a Modificar e Software Criador.</li>"
            "<li><b>Áudio (MP3, WAV, FLAC...):</b> Duração Exata, Taxa de Bits (Bitrate), Artista/Software e Comentários Ocultos.</li>"
            "<li><b>Executáveis (EXE, DLL, SYS):</b> Data de Compilação Exata (UTC), Verificação de Assinatura Digital (Authenticode), Nome Original do Arquivo e Empresa.</li>"
            "<li><b>E-mails (EML, MSG):</b> Remetente Real, Destinatário, Assunto, Data de Envio e 1º Servidor de Trânsito (rastreio de IP).</li>"
            "<li><b>Arquivos Geográficos (KML, KMZ, GPX, XML):</b> Extração de pontos e vértices (com supressão inteligente de coordenadas duplicadas) e leitura do total geográfico exato.</li>"
            "<li><b>Atalhos do Windows (LNK):</b> Caminho Alvo (Local e Relativo), Argumentos de Execução (Payloads), Diretório de Trabalho, Rótulo/Serial do Pendrive/HD (em Hex) e MAC Address de origem.</li>"
            "</ul>"
            "<p><b>Análises Forenses Integradas e Proteções:</b></p>"
            "<ul>"
            "<li><b>Segurança NTFS (ADS):</b> Detecção e leitura parcial de fluxos de dados ocultos, como 'Mark of the Web' ou payloads binários.</li>"
            "<li><b>Preservação de Evidência (Nuvem):</b> Bloqueio automático de leitura de arquivos 'Apenas Online' (OneDrive/Google Drive) para evitar downloads indesejados e alteração do disco.</li>"
            "<li><b>Seleção Literal:</b> Ignora ativamente resoluções nativas do Windows para links simbólicos e junções de diretório.</li>"
            "<li><b>File Lock / Controle de Acesso:</b> Identificação segura de arquivos trancados com acesso exclusivo pelo sistema operacional ou em uso por outros aplicativos (ex: pacote Office).</li>"
            "</ul>"
        )
        self.chk_metadados.installEventFilter(self)
        layout_opcoes_metadados.addWidget(self.chk_metadados)

        self.chk_metadados_raw = QCheckBox("Incluir TODOS os metadados (Raw Dump)")
        self.chk_metadados_raw.setChecked(False)
        self.chk_metadados_raw.setToolTip(
            "Anexa o dicionário completo e bruto de metadados extraídos\npelas bibliotecas ao final do relatório de cada arquivo.")
        self.chk_metadados_raw.installEventFilter(self)
        layout_opcoes_metadados.addWidget(self.chk_metadados_raw)

        self.chk_metadados.clicked.connect(self._garantir_exclusividade_basico)
        self.chk_metadados_raw.clicked.connect(self._garantir_exclusividade_raw)

        layout_hashes.addLayout(layout_opcoes_metadados)
        layout_hashes.addStretch()

        # Adiciona a segunda linha dentro da caixa
        layout_grupo_controles.addLayout(layout_hashes)

        # Finalmente, define o layout empilhado na caixa e coloca a caixa na janela
        self.grupo_controles.setLayout(layout_grupo_controles)
        layout_principal.addWidget(self.grupo_controles)

        # ==============================================================
        # CONTAINER MÓVEL DOS RESULTADOS (Será teletransportado)
        # ==============================================================
        self.painel_resultados = QWidget()
        layout_resultados = QVBoxLayout(self.painel_resultados)
        layout_resultados.setContentsMargins(0, 5, 0, 0)

        # --- ALERTA DE ATUALIZAÇÃO (Invisível por padrão) ---
        self.lbl_alerta_versao = QLabel()
        self.lbl_alerta_versao.setOpenExternalLinks(False)  # Para o link funcionar
        self.lbl_alerta_versao.hide()  # Esconde ao iniciar

        self.lbl_alerta_versao.linkActivated.connect(self._tratar_clique_atualizacao)

        layout_resultados.addWidget(self.lbl_alerta_versao)

        # =====================================================================
        # 1. BOTÃO DA SANFONA (Inicia invisível, pois o padrão é o Clássico)
        # =====================================================================
        self.btn_toggle_custodia = QPushButton("▶ Validar Cadeia de Custódia (Opcional - Clique para expandir)")
        self.btn_toggle_custodia.setStyleSheet("""
                    QPushButton {
                        text-align: left;
                        font-weight: bold;
                        padding: 8px;
                        background-color: #e0e0e0;
                        color: #333333;
                        border: 1px solid #cccccc;
                        border-radius: 3px;
                        margin-top: 10px;
                    }
                    QPushButton:hover { background-color: #d5d5d5; }
                """)
        self.btn_toggle_custodia.hide()  # <-- Escondido por padrão!
        layout_resultados.addWidget(self.btn_toggle_custodia)

        # --- DIVISOR AJUSTÁVEL (QSplitter) ---
        splitter = QSplitter(Qt.Orientation.Vertical)

        # =====================================================================
        # 2. CAIXA DE CUSTÓDIA (Volta a ser o QGroupBox Clássico por padrão)
        # =====================================================================
        self.grupo_validacao = QGroupBox("Validar Cadeia de Custódia (Opcional)")

        # Guardamos as duas "roupas" em variáveis da classe
        self.estilo_custodia_classico = """
                    QGroupBox { border: 1px solid #cccccc; margin-top: 10px; border-radius: 3px; padding-top: 5px; }
                    QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; color: #111111; }
                """
        self.estilo_custodia_moderno = """
                    QGroupBox { border: 1px solid #cccccc; border-top: none; margin-top: 0px; padding-top: 5px; background-color: #fafafa; }
                """
        # Veste a roupa clássica ao abrir o programa
        self.grupo_validacao.setStyleSheet(self.estilo_custodia_classico)

        layout_validacao = QHBoxLayout(self.grupo_validacao)
        layout_validacao.setContentsMargins(5, 5, 5, 5)

        self.texto_referencia = TextEditCustodia(self)
        self.texto_referencia.setMinimumHeight(100)

        self.btn_limpar_custodia = QPushButton("Limpar\nConteúdo")
        self.btn_limpar_custodia.setFixedWidth(80)
        self.btn_limpar_custodia.setSizePolicy(self.btn_limpar_custodia.sizePolicy().Policy.Fixed,
                                               self.btn_limpar_custodia.sizePolicy().Policy.Expanding)
        self.btn_limpar_custodia.clicked.connect(self.texto_referencia.clear)

        layout_validacao.addWidget(self.texto_referencia)
        layout_validacao.addWidget(self.btn_limpar_custodia)

        # Adiciona a caixa no splitter (Agora ela NÃO recebe mais .hide() aqui, fica sempre visível no clássico)
        splitter.addWidget(self.grupo_validacao)

        # --- Lógica da Sanfona ---
        def alternar_sanfona():
            esta_visivel = self.grupo_validacao.isVisible()
            self.grupo_validacao.setVisible(not esta_visivel)

            if esta_visivel:
                self.btn_toggle_custodia.setText("▶ Validar Cadeia de Custódia (Opcional - Clique para expandir)")
            else:
                self.btn_toggle_custodia.setText("▼ Validar Cadeia de Custódia (Clique para recolher)")
                splitter.setSizes([110, 470])

        self.btn_toggle_custodia.clicked.connect(alternar_sanfona)

        # --- Área de Texto Principal (Envelopada com Título Padronizado) ---
        self.grupo_saida = QGroupBox("Área de Extração Forense (Resultados)")
        self.grupo_saida.setStyleSheet("""
                            QGroupBox { border: 1px solid #cccccc; margin-top: 10px; border-radius: 3px; padding-top: 5px; }
                            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; color: #111111; }
                        """)
        layout_interno_saida = QVBoxLayout()
        layout_interno_saida.setContentsMargins(6, 12, 6, 6)  # Pequeno espaçamento interno para a caixa respirar

        self.texto_saida = QTextEdit()
        self.texto_saida.setReadOnly(True)
        self.texto_saida.setStyleSheet(
            "background-color: #f4f4f4; color: #111111; font-family: Consolas; font-size: 10pt;")

        layout_interno_saida.addWidget(self.texto_saida)
        self.grupo_saida.setLayout(layout_interno_saida)

        # ==========================================================
        # INTERCEPTAÇÃO DE TEXTO PARA PROTEÇÃO DE MEMÓRIA (UI FREEZE)
        # ==========================================================
        self._relatorio_memoria = []
        self._chars_na_tela = 0
        self._limite_tela_atingido = False

        # Guardamos as funções nativas do C++ do PySide6
        self.texto_saida._original_append = self.texto_saida.append
        self.texto_saida._original_clear = self.texto_saida.clear

        def append_seguro(texto):
            # 1. Salva sempre o dado real na lista invisível (super rápido)
            self._relatorio_memoria.append(texto)

            # Se a tela estava bloqueada para seleção, libera para o log real
            if self.texto_saida.textInteractionFlags() == Qt.TextInteractionFlag.NoTextInteraction:
                self.texto_saida.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)

            # 2. Joga para a interface gráfica só se não tiver estourado o limite (500.000 chars)
            if not self._limite_tela_atingido:
                # Protege os caracteres menores/maiores para não quebrarem o HTML do PySide6
                texto_tela = texto.replace('<', '&lt;').replace('>', '&gt;')
                self.texto_saida._original_append(texto_tela)
                self._chars_na_tela += len(texto)

                if self._chars_na_tela > 500000:
                    self._limite_tela_atingido = True
                    aviso_corte = (
                        "\n\n====================================================================\n"
                        "⚠️ ATENÇÃO: RELATÓRIO MUITO EXTENSO PARA EXIBIÇÃO VISUAL ⚠️\n"
                        "====================================================================\n"
                        "Para evitar o congelamento da interface, a exibição em tela foi pausada.\n"
                        "A extração dos dados CONTINUA normalmente em segundo plano.\n\n"
                        "👉 COMO ACESSAR O LAUDO COMPLETO:\n"
                        "   1. Aguarde o progresso finalizar (Mensagem de 'Concluído').\n"
                        "   2. Clique em 'Salvar Relatório em TXT' ou 'Copiar Relatório'.\n"
                        "===================================================================="
                    )
                    self.texto_saida._original_append(aviso_corte)

        def clear_seguro():
            # Limpa simultaneamente a tela e a memória
            self._relatorio_memoria.clear()
            self._chars_na_tela = 0
            self._limite_tela_atingido = False
            self.texto_saida._original_clear()

        # Substitui os métodos da caixa de texto pelos métodos seguros
        self.texto_saida.append = append_seguro
        self.texto_saida.clear = clear_seguro
        # ==========================================================

        # Insere o texto plano na memória (para o TXT) e o HTML na tela
        self._relatorio_memoria.append(MENSAGEM_INICIAL + "\n")

        # noinspection PyArgumentList
        self.texto_saida._original_append(MENSAGEM_VISUAL)

        self._chars_na_tela += len(MENSAGEM_VISUAL)

        # Bloqueia a seleção da MENSAGEM_VISUAL inicial
        self.texto_saida.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)

        # Adiciona a saída também no splitter, para ficar embaixo da validação
        splitter.addWidget(self.grupo_saida)

        # =====================================================================
        # AJUSTE DE COMPORTAMENTO DO SPLITTER
        # =====================================================================
        splitter.setStretchFactor(0, 0)  # Caixa de Custódia: Não estica
        splitter.setStretchFactor(1, 1)  # Área de Texto Principal: Absorve o crescimento
        # =====================================================================

        # Define as proporções iniciais de altura
        splitter.setSizes([110, 470])

        # Finalmente, coloca o splitter inteiro na tela principal
        layout_resultados.addWidget(splitter, stretch=1)

        # --- Barras de Progresso ---
        layout_progresso = QVBoxLayout()

        # Estilo padrão para as barras (Fundo escuro/Grafite e Letra Branca)
        self.estilo_barra_padrao = """
                    QProgressBar {
                        border: 1px solid #999999;
                        border-radius: 4px;
                        text-align: center;
                        background-color: #333333;
                        color: #ffffff;
                        font-weight: bold;
                    }
                    QProgressBar::chunk {
                        background-color: #0078d7;
                        border-radius: 2px;
                    }
                """

        # 1. Progresso do Arquivo Atual
        self.lbl_progresso_arquivo = QLabel("Progresso do Arquivo Atual:")
        layout_progresso.addWidget(self.lbl_progresso_arquivo)

        self.barra_arquivo = QProgressBar()
        self.barra_arquivo.setValue(0)
        self.barra_arquivo.setStyleSheet(self.estilo_barra_padrao)
        layout_progresso.addWidget(self.barra_arquivo)

        layout_progresso.addSpacing(5)  # Pequeno respiro entre as barras

        # 2. Progresso Total (Arquivos)
        self.lbl_progresso_total = QLabel("Progresso Total (Arquivos):")
        layout_progresso.addWidget(self.lbl_progresso_total)

        self.barra_total = QProgressBar()
        self.barra_total.setValue(0)
        self.barra_total.setStyleSheet(self.estilo_barra_padrao)

        layout_progresso.addWidget(self.barra_total)

        layout_progresso.addSpacing(10)  # Espaço maior antes do botão

        # 3. Botão Cancelar em linha dedicada e centralizado
        self.btn_cancelar = QPushButton("CANCELAR PROCESSAMENTO")
        self.btn_cancelar.setMinimumWidth(280)
        self.btn_cancelar.setMinimumHeight(40)
        self.btn_cancelar.setStyleSheet("""
                            QPushButton {
                                background-color: #ffcccc; 
                                color: #990000; 
                                font-weight: bold;
                                border: 1px solid #cc9999;
                                border-radius: 5px;
                            }
                            QPushButton:hover {
                                background-color: #ffb3b3; /* Vermelho um pouco mais forte ao passar o mouse */
                                border: 1px solid #b30000;
                            }
                            QPushButton:pressed {
                                background-color: #ff9999; /* Vermelho ainda mais escuro ao clicar */
                            }
                            QPushButton:disabled {
                                background-color: #e0e0e0; 
                                color: #888888;
                                border: 1px solid #cccccc;
                            }
                        """)
        self.btn_cancelar.setEnabled(False)
        self.btn_cancelar.clicked.connect(self.acao_cancelar)

        # Adicionado diretamente ao layout vertical para expandir totalmente
        layout_progresso.addWidget(self.btn_cancelar)

        layout_resultados.addLayout(layout_progresso)

        # --- Barra Inferior ---
        layout_inferior = QHBoxLayout()

        self.btn_copiar = QPushButton("Copiar Relatório (Ctrl+C)")
        self.btn_copiar.clicked.connect(self.copiar_para_area_transferencia)
        layout_inferior.addWidget(self.btn_copiar)

        self.btn_salvar = QPushButton("Salvar Relatório em TXT")
        self.btn_salvar.clicked.connect(self.salvar_relatorio)
        layout_inferior.addWidget(self.btn_salvar)

        self.btn_limpar = QPushButton("Limpar Tela")
        self.btn_limpar.clicked.connect(self.limpar_tela)
        layout_inferior.addWidget(self.btn_limpar)

        layout_resultados.addLayout(layout_inferior)

        # Sincroniza a cor e o nome do botão do Write-Blocker com o status real do Windows ao abrir
        self.atualizar_ui_write_blocker()

        # --- Monitoramento Contínuo do Registro (A cada 2 segundos) ---
        self.timer_wb = QTimer(self)
        self.timer_wb.timeout.connect(self.atualizar_ui_write_blocker)
        self.timer_wb.start(2000)  # 2000 milissegundos = 2 segundos

        # Carregar configurações salvas
        config = carregar_config()

        # Gera a tooltip do Write-Blocker com a cor correta do tema carregado
        self.atualizar_tooltip_wb()

        if config:
            # JÁ EXISTE CONFIGURAÇÃO SALVA: Respeita a escolha anterior do usuário
            # Restaura o Modo Escuro primeiro para não piscar a tela clara
            self.chk_modo_escuro.setChecked(config.get('chk_modo_escuro', False))

            # Restaura estado do checkbox de metadados
            self.chk_metadados.setChecked(config.get('chk_metadados', True))

            # Restaura o Raw Dump (Padrão: False)
            self.chk_metadados_raw.setChecked(config.get('chk_metadados_raw', False))

            # Garante que não iniciem ambas marcadas pelo cache antigo
            if self.chk_metadados.isChecked() and self.chk_metadados_raw.isChecked():
                self.chk_metadados_raw.setChecked(False)

            # Restaura estado do checkbox de subdiretórios
            self.chk_subdiretorios.setChecked(config.get('chk_subdiretorios', True))

            # Restaura estados dos algoritmos
            hash_states = config.get('hashes', {})
            for algo, chk in self.chk_hashes.items():
                chk.setChecked(hash_states.get(algo, algo in ["SHA-256", "SHA-512"]))

        else:
            # PRIMEIRA EXECUÇÃO (config.dat não existe): Detecta o tema do Windows
            esquema_cor = QApplication.styleHints().colorScheme()

            # Se o Windows estiver configurado para o Modo Escuro, ativa o checkbox
            if esquema_cor == Qt.ColorScheme.Dark:
                self.chk_modo_escuro.setChecked(True)

            # Força a criação do config.dat imediatamente na primeira abertura
            self.salvar_estado_atual()

        # --- Salvar em tempo real ---
        self.chk_modo_escuro.toggled.connect(self.salvar_estado_atual)
        self.chk_metadados.toggled.connect(self.salvar_estado_atual)
        self.chk_metadados_raw.toggled.connect(self.salvar_estado_atual)
        self.chk_subdiretorios.toggled.connect(self.salvar_estado_atual)
        for chk in self.chk_hashes.values():
            chk.toggled.connect(self.salvar_estado_atual)

        # ==============================================================
        # Adiciona o contêiner móvel ao layout clássico para ele nascer lá
        layout_principal.addWidget(self.painel_resultados, stretch=1)

        # Salva uma referência deste layout para usarmos no teletransporte
        self.layout_classico = layout_principal

    def setup_ui_moderno(self, parent_widget):
        layout_moderno = QVBoxLayout(parent_widget)
        layout_moderno.setContentsMargins(0, 0, 0, 0)
        layout_moderno.setSpacing(0)

        # ==============================================================
        # 1. LINHA SUPERIOR (BOTÃO FORENSE + BARRA DE MENUS LADO A LADO)
        # ==============================================================
        layout_linha_topo = QHBoxLayout()
        layout_linha_topo.setContentsMargins(5, 0, 0, 0)  # Margem leve para não grudar na parede
        layout_linha_topo.setSpacing(0)
        # Força a linha inteira a se alinhar pelo centro vertical
        layout_linha_topo.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        # --- BOTÃO 1: ESCRITA USB (Fora do QMenuBar para garantir que não vai sumir) ---
        self.btn_menu_protecao = QPushButton("🔒 USB: Verificando...")
        self.btn_menu_protecao.setCursor(Qt.CursorShape.PointingHandCursor)

        menu_drop_protecao = QMenu(self)
        self.action_bloquear_usb = QAction("🔒 Bloquear Escrita em USB", self)
        self.action_bloquear_usb.triggered.connect(self.alternar_write_blocker)
        menu_drop_protecao.addAction(self.action_bloquear_usb)

        self.action_desbloquear_usb = QAction("🔓 Desbloquear Escrita em USB", self)
        self.action_desbloquear_usb.triggered.connect(self.alternar_write_blocker)
        menu_drop_protecao.addAction(self.action_desbloquear_usb)

        self.btn_menu_protecao.setMenu(menu_drop_protecao)

        # Adiciona o botão no começo (à esquerda) forçando o alinhamento central
        layout_linha_topo.addWidget(self.btn_menu_protecao, alignment=Qt.AlignmentFlag.AlignVCenter)

        # --- BARRA DE MENUS (Restante das opções) ---
        barra_menus = QMenuBar()

        # --- MENU 2: SELEÇÃO MANUAL ---
        menu_selecao = barra_menus.addMenu("📂 Seleção Manual")

        action_arquivo = QAction("Selecionar Arquivo(s)", self)
        action_arquivo.triggered.connect(self.selecionar_arquivo)
        menu_selecao.addAction(action_arquivo)

        action_diretorio = QAction("Selecionar Diretório", self)
        action_diretorio.triggered.connect(self.selecionar_diretorio)
        menu_selecao.addAction(action_diretorio)

        action_raw = QAction("Selecionar Unidade (RAW)", self)
        action_raw.triggered.connect(self.selecionar_unidade_raw)
        menu_selecao.addAction(action_raw)

        # --- MENU 3: ALGORITMOS DE HASH ---
        menu_hashes = barra_menus.addMenu("🔢 Algoritmos de Hash")
        self.acoes_hashes_moderno = {}

        for algo in ["CRC32", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]:
            # Cria a ação especial que permite embutir widgets
            acao_widget = QWidgetAction(self)

            # Cria um CheckBox real (com um espacinho para ficar alinhado no menu)
            chk_box = QCheckBox(f"  {algo}")

            # Deixa ele um pouco mais espaçado e bonito para o menu
            chk_box.setStyleSheet("padding: 5px; margin-left: 10px;")

            # Herda o estado do modo clássico
            chk_box.setChecked(self.chk_hashes[algo].isChecked())

            # Sincroniza com o modo clássico (Backend) quando for clicado.
            # NOTA: O "a=algo" é um truque do Python para o lambda não se perder no loop!
            chk_box.toggled.connect(lambda checked, a=algo: self.chk_hashes[a].setChecked(checked))

            # Embute o Checkbox na ação e a ação no menu
            acao_widget.setDefaultWidget(chk_box)
            menu_hashes.addAction(acao_widget)

            # Guarda a referência caso precise acessar depois
            self.acoes_hashes_moderno[algo] = chk_box

        # --- MENU 4: METADADOS ---
        menu_meta = barra_menus.addMenu("🏷️ Metadados")

        # 1. Cria a ação especial e o CheckBox para Metadados Básicos
        acao_meta_basico = QWidgetAction(self)
        self.chk_meta_basico_moderno = QCheckBox("  Incluir Metadados Básicos")
        self.chk_meta_basico_moderno.setStyleSheet("padding: 5px; margin-left: 10px;")
        self.chk_meta_basico_moderno.setChecked(self.chk_metadados.isChecked())
        acao_meta_basico.setDefaultWidget(self.chk_meta_basico_moderno)
        menu_meta.addAction(acao_meta_basico)

        # 2. Cria a ação especial e o CheckBox para Metadados Raw
        acao_meta_raw = QWidgetAction(self)
        self.chk_meta_raw_moderno = QCheckBox("  Incluir TODOS os metadados (Raw Dump)")
        self.chk_meta_raw_moderno.setStyleSheet("padding: 5px; margin-left: 10px;")
        self.chk_meta_raw_moderno.setChecked(self.chk_metadados_raw.isChecked())
        acao_meta_raw.setDefaultWidget(self.chk_meta_raw_moderno)
        menu_meta.addAction(acao_meta_raw)

        # Lógica de Exclusividade (Um ou Nenhum) + Sincronização com o Backend
        def alternar_meta_basico(checked):
            if checked:
                # Bloqueia temporariamente a emissão de sinais do outro checkbox
                # para que ele seja desmarcado silenciosamente, sem disparar outro evento
                self.chk_meta_raw_moderno.blockSignals(True)
                self.chk_meta_raw_moderno.setChecked(False)
                self.chk_metadados_raw.setChecked(False)  # Sincroniza backend
                self.chk_meta_raw_moderno.blockSignals(False)

            # Atualiza o backend com o estado atual do checkbox clicado
            self.chk_metadados.setChecked(checked)

        def alternar_meta_raw(checked):
            if checked:
                # Bloqueia temporariamente a emissão de sinais do outro checkbox
                self.chk_meta_basico_moderno.blockSignals(True)
                self.chk_meta_basico_moderno.setChecked(False)
                self.chk_metadados.setChecked(False)  # Sincroniza backend
                self.chk_meta_basico_moderno.blockSignals(False)

            # Atualiza o backend com o estado atual do checkbox clicado
            self.chk_metadados_raw.setChecked(checked)

        # Conectando as funções aos cliques nos novos checkboxes modernos
        self.chk_meta_basico_moderno.toggled.connect(alternar_meta_basico)
        self.chk_meta_raw_moderno.toggled.connect(alternar_meta_raw)

        # ==============================================================
        # ITENS DIRETOS NA BARRA DE MENUS (Agem como botões)
        # ==============================================================

        # Adiciona um espaço visual (apenas estético, se o estilo permitir)
        barra_menus.addSeparator()

        action_formatos = QAction("📚 Formatos Suportados", self)
        action_formatos.triggered.connect(self.mostrar_formatos)
        barra_menus.addAction(action_formatos)  # Adicionado direto na barra, não em um menu

        action_manual = QAction("📖 Manual Online", self)
        action_manual.triggered.connect(self.abrir_manual_online)
        barra_menus.addAction(action_manual)

        action_sobre = QAction("ℹ️ Sobre", self)
        action_sobre.triggered.connect(self.mostrar_sobre)
        barra_menus.addAction(action_sobre)

        # --- LÓGICA DO MODO ESCURO / CLARO ---
        # Define o estado inicial baseado no checkbox do modo clássico
        estado_inicial_escuro = self.chk_modo_escuro.isChecked()
        texto_tema_inicial = "☀️ Modo Claro" if estado_inicial_escuro else "🌙 Modo Escuro"

        self.action_tema = QAction(texto_tema_inicial, self)
        self.action_tema.setCheckable(True)
        self.action_tema.setChecked(estado_inicial_escuro)

        # Função interna rápida para trocar o texto e acionar a sua função original
        def alternar_tema_wrapper(checked):
            self.action_tema.setText("☀️ Modo Claro" if checked else "🌙 Modo Escuro")
            # Ao alterar o checkbox original, ele dispara o sinal que já aciona a sua
            # função self.alternar_modo_escuro(checked) automaticamente!
            self.chk_modo_escuro.setChecked(checked)

        self.action_tema.toggled.connect(alternar_tema_wrapper)
        barra_menus.addAction(self.action_tema)
        # Adiciona a barra de menus à direita, preenchendo o espaço (stretch=1) e forçando centro
        layout_linha_topo.addWidget(barra_menus, stretch=1, alignment=Qt.AlignmentFlag.AlignVCenter)

        # Adiciona a linha inteira no topo da tela moderna
        layout_moderno.addLayout(layout_linha_topo)

        self.layout_moderno = layout_moderno

    def alternar_visual(self):
        if self.stacked_widget.currentIndex() == 0:
            # ==============================================================
            # INDO PARA O MODO MODERNO
            # ==============================================================
            self.stacked_widget.setCurrentIndex(1)
            self.btn_alternar_visual.setText("Voltar para Visual Clássico")

            self.layout_moderno.addWidget(self.painel_resultados, stretch=1)
            self.painel_resultados.layout().setContentsMargins(10, 10, 10, 10)

            # --- Transforma a Custódia em Sanfona ---
            self.grupo_validacao.setTitle("")  # Apaga o título do GroupBox
            self.grupo_validacao.setStyleSheet(self.estilo_custodia_moderno)  # Tira a borda superior
            self.btn_toggle_custodia.show()  # Mostra o botão clicável da sanfona

            # Força o fechamento da sanfona para focar no drag & drop
            self.grupo_validacao.hide()
            self.btn_toggle_custodia.setText("▶ Validar Cadeia de Custódia (Opcional - Clique para expandir)")

        else:
            # ==============================================================
            # VOLTANDO PARA O MODO CLÁSSICO
            # ==============================================================
            self.stacked_widget.setCurrentIndex(0)
            self.btn_alternar_visual.setText("Alternar para Visual Moderno (Foco em Drag & Drop)")

            self.layout_classico.addWidget(self.painel_resultados, stretch=1)
            self.painel_resultados.layout().setContentsMargins(0, 5, 0, 0)

            # --- Restaura a Custódia Clássica Original ---
            self.grupo_validacao.setTitle("Validar Cadeia de Custódia (Opcional)")  # Devolve o título
            self.grupo_validacao.setStyleSheet(self.estilo_custodia_classico)  # Devolve as bordas
            self.btn_toggle_custodia.hide()  # Esconde o botão da sanfona

            # Garante que a caixa de texto volte a ficar 100% visível na tela
            self.grupo_validacao.show()

    def _verificar_status_wb(self):
        """Verifica de forma silenciosa se o bloqueio de escrita USB está ativo no registro."""
        try:
            chave = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies")
            valor, _ = winreg.QueryValueEx(chave, "WriteProtect")
            winreg.CloseKey(chave)
            return valor == 1
        except Exception:
            return False

    def atualizar_ui_write_blocker(self):
        """Muda o texto e a cor do botão baseando-se no registro, garantindo contraste invertido para destaque."""
        ativo = self._verificar_status_wb()
        is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()

        # --- DEFINIÇÃO DOS ESTILOS (QSS) ---

        # 1. ESTILO: ATIVADO (Sempre Vermelho Vivo para alerta)
        estilo_ativo = """
            QPushButton {
                font-weight: bold; color: #ffffff; background-color: #990000; border: 1px solid #770000; padding: 4px; border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #cc0000;
                border: 1px solid #990000;
            }
            QPushButton:pressed {
                background-color: #660000;
                padding-top: 5px; padding-bottom: 3px;
            }
            QPushButton:disabled {
                background-color: #cc9999; color: #f0f0f0; border: 1px solid #bb8888;
            }
        """

        # 2. ESTILO INVERTIDO: DESATIVADO NO MODO ESCURO (Botão Claro)
        estilo_inativo_escuro = """
            QPushButton {
                font-weight: bold; color: #111111; background-color: #e0e0e0; border: 1px solid #cccccc; padding: 4px; border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #ffffff;
                border: 1px solid #aaaaaa;
            }
            QPushButton:pressed {
                background-color: #c0c0c0;
                padding-top: 5px; padding-bottom: 3px;
            }
            QPushButton:disabled {
                background-color: #2b2b2b; color: #666666; border: 1px solid #444444; font-weight: normal;
            }
        """

        # 3. ESTILO INVERTIDO: DESATIVADO NO MODO CLARO (Botão Escuro)
        estilo_inativo_claro = """
            QPushButton {
                font-weight: bold; color: #f0f0f0; background-color: #3c3f41; border: 1px solid #555555; padding: 4px; border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #4c4f51;
                border: 1px solid #777777;
            }
            QPushButton:pressed {
                background-color: #2c2f31;
                padding-top: 5px; padding-bottom: 3px;
            }
            QPushButton:disabled {
                background-color: #e0e0e0; color: #888888; border: 1px solid #cccccc; font-weight: normal;
            }
        """

        # --- 1. APLICAÇÃO DOS ESTILOS NO MODO CLÁSSICO ---
        if hasattr(self, 'btn_write_blocker'):
            if ativo:
                self.btn_write_blocker.setText("DESBLOQUEAR ESCRITA EM USB")
                self.btn_write_blocker.setStyleSheet(estilo_ativo)
            else:
                self.btn_write_blocker.setText("BLOQUEAR ESCRITA EM USB")
                # Aplica o estilo de alto contraste baseado no tema
                if is_dark:
                    self.btn_write_blocker.setStyleSheet(estilo_inativo_escuro)
                else:
                    self.btn_write_blocker.setStyleSheet(estilo_inativo_claro)

        # --- 2. ATUALIZAÇÃO DA INTERFACE MODERNA (Menu) ---
        if hasattr(self, 'btn_menu_protecao'):
            if ativo:
                # Estado BLOQUEADO (Seguro) - Estilo Vermelho Vivo Alerta
                self.btn_menu_protecao.setText("🔒 USB: ESCRITA BLOQUEADA")
                self.btn_menu_protecao.setStyleSheet("""
                    QPushButton {
                        background-color: #990000;
                        color: #ffffff;
                        font-weight: bold;
                        border: 1px solid #770000;
                        border-radius: 4px;
                        padding: 4px 10px;
                        margin-right: 5px;
                        min-height: 22px;
                    }
                    QPushButton:hover { background-color: #cc0000; }
                    QPushButton::menu-indicator { image: none; }
                """)
                self.action_bloquear_usb.setEnabled(False)
                self.action_desbloquear_usb.setEnabled(True)
            else:
                # Estado PERMITIDO (Atenção) - Estilo Neutro Invertido
                self.btn_menu_protecao.setText("⚠️ USB: ESCRITA PERMITIDA")

                # Aproveita os estilos da interface clássica, forçando a altura mínima
                css_base = estilo_inativo_escuro if is_dark else estilo_inativo_claro
                css_adaptado = css_base + "\nQPushButton { margin-right: 5px; padding: 4px 10px; min-height: 22px; }\nQPushButton::menu-indicator { image: none; }"

                self.btn_menu_protecao.setStyleSheet(css_adaptado)
                self.action_bloquear_usb.setEnabled(True)
                self.action_desbloquear_usb.setEnabled(False)

    def atualizar_tooltip_wb(self):
        """Atualiza a cor de alerta da tooltip baseando-se no tema claro/escuro."""
        # Verifica se o modo escuro está ativado
        is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()

        # Define a cor ideal para cada fundo
        # #ff5555 = Vermelho vivo/claro (ótimo para fundos escuros)
        # #990000 = Vermelho escuro (ótimo para fundos claros)
        cor_alerta = "#ff5555" if is_dark else "#990000"

        self.btn_write_blocker.setToolTip(
            "<p><b>Software Write-Blocker (Bloqueio de Registro)</b></p>"
            "<ul>"
            "<li>Impede que o Windows grave arquivos ou altere atributos em mídias USB.</li>"
            "<li><b>Como usar:</b> Ative o bloqueio ANTES de plugar o pendrive/HD na entrada USB da máquina.</li>"
            "</ul>"
            f"<p><span style='color: {cor_alerta};'><b>⚠️ AVISO PERICIAL:</b> O bloqueio lógico via software é um método seguro e "
            "com pleno valor probatório para a preservação de evidências, desde que seja seguido o protocolo correto: ativação do "
            "bloqueio <b>ANTES</b> da conexão do dispositivo à entrada USB. Contudo, as diretrizes forenses internacionais mantêm o "
            "<b>Hardware Write-Blocker (Bloqueador Físico)</b> como <b>Padrão-Ouro</b>, pois, ao atuar na camada física, ele elimina "
            "os riscos de eventuais falhas de procedimento e/ou instabilidades do Sistema Operacional.</span></p>"
        )

    def alternar_write_blocker(self):
        """Dispara a janela do UAC apenas para a alteração de registro, sem elevar o aplicativo inteiro."""
        ativo = self._verificar_status_wb()
        novo_valor = 0 if ativo else 1
        acao_nome = "Desbloqueio" if ativo else "Bloqueio"

        # O comando 'reg.exe add' é a forma mais nativa e estável do Windows.
        # Ele cria a pasta StorageDevicePolicies caso não exista e injeta o DWORD silenciosamente (/f).
        argumentos_reg = f"add HKLM\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies /v WriteProtect /t REG_DWORD /d {novo_valor} /f"

        comando = [
            "powershell",
            "-NoProfile",
            "-WindowStyle", "Hidden",
            "-Command",
            f"Start-Process -FilePath 'reg.exe' -ArgumentList '{argumentos_reg}' -Verb RunAs -WindowStyle Hidden -Wait"
        ]

        try:
            import subprocess
            # Ao rodar isso, apenas o comando 'reg.exe' pedirá permissão de Administrador (UAC).
            # O programa Python ficará aguardando o usuário clicar em "Sim" ou "Não" na tela do Windows.
            subprocess.run(comando, creationflags=0x08000000)

            # Atualiza o botão visualmente
            self.atualizar_ui_write_blocker()

            # Verifica se a alteração realmente surtiu efeito no registro
            status_atualizado = self._verificar_status_wb()
            esperado_ativo = (novo_valor == 1)

            if status_atualizado == esperado_ativo:
                msg = QMessageBox(self)
                msg.setWindowTitle("Status do Software Write-Blocker")

                # --- Verifica o tema atual e define as cores ideais ---
                is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
                cor_vermelha = "#ff5555" if is_dark else "#cc0000"  # Vermelho claro no escuro, escuro no claro
                cor_verde = "#55cc55" if is_dark else "#007700"  # Verde claro no escuro, escuro no claro

                # Se estamos ATIVANDO o bloqueio (novo_valor == 1)
                if esperado_ativo:
                    msg.setIcon(QMessageBox.Icon.Warning)
                    # Usa f-string (f"...") para injetar a cor verde dinâmica
                    msg.setText(
                        f"<h3 style='margin: 0;'>Bloqueio de Escrita USB <span style='color: {cor_verde};'>ATIVADO</span>!</h3>")
                    # Usa f-string para injetar a cor vermelha dinâmica nos alertas
                    msg.setInformativeText(
                        f"<div style='font-size: 11pt;'>"
                        f"<p><b style='color: {cor_vermelha}; font-size: 13pt;'>⚠️ ATENÇÃO EXTREMA:</b></p>"
                        f"<p>Qualquer pendrive ou HD que <b>JÁ ESTIVESSE PLUGADO</b> antes de você clicar neste botão "
                        f"<b style='color: {cor_vermelha}; font-size: 13pt;'><u>NÃO ESTÁ PROTEGIDO</u></b> contra gravação pelo Windows!</p>"
                        f"<p>Para garantir a inalterabilidade da evidência, você deve conectá-la na porta USB <b>SOMENTE AGORA</b>.</p>"
                        f"<p><i>(Se a unidade a ser periciada já estava conectada, ejete-a e reconecte-a novamente para protegê-la.)</i></p>"
                        f"</div>"
                    )
                # Se estamos DESATIVANDO o bloqueio (novo_valor == 0)
                else:
                    msg.setIcon(QMessageBox.Icon.Information)
                    msg.setText(
                        f"<h3 style='margin: 0;'>Bloqueio de Escrita USB <span style='color: {cor_vermelha};'>DESATIVADO</span>!</h3>")
                    msg.setInformativeText(
                        "<div style='font-size: 11pt;'>"
                        "<p>As portas USB voltaram ao comportamento padrão do sistema.</p>"
                        "<p>Qualquer dispositivo inserido a partir de agora poderá sofrer alterações, indexações ou gravação de arquivos pelo Windows.</p>"
                        "</div>"
                    )

                msg.exec()
            else:
                msg_erro = QMessageBox(self)
                msg_erro.setWindowTitle("Aviso - Alteração Cancelada")
                msg_erro.setIcon(QMessageBox.Icon.Warning)
                msg_erro.setText("<h3 style='margin: 0; color: #cc6600;'>O registro NÃO foi alterado.</h3>")
                msg_erro.setInformativeText(
                    "<div style='font-size: 11pt;'>"
                    "<p>A operação falhou. Os motivos mais comuns são:</p>"
                    "<ul>"
                    "<li>Você <b>cancelou</b> a autorização na tela do Windows (UAC).</li>"
                    "<li>As credenciais de Administrador inseridas estão incorretas.</li>"
                    "<li><b>Bloqueio de TI (GPO):</b> O computador possui políticas corporativas que negam silenciosamente a elevação de privilégios para usuários padrão.</li>"
                    "</ul>"
                    "<p>Nenhuma modificação foi feita no sistema. <b>O status das portas USB permanece inalterado.</b></p>"
                    "</div>"
                )
                msg_erro.exec()

        except Exception as e:
            QMessageBox.critical(self, "Erro Forense", f"Falha ao tentar modificar as políticas de USB: {e}")

    def _verificar_pre_extracao_custodia(self, texto_custodia):
        """
        Checagem de segurança antes da extração.
        Retorna o 'texto_custodia' se puder prosseguir (ou "" para desativar a validação),
        e retorna None se o usuário abortar a operação.
        """
        if not texto_custodia:
            return texto_custodia

        padroes = {
            "MD5": r'\b[a-fA-F0-9]{32}\b',
            "SHA-1": r'\b[a-fA-F0-9]{40}\b',
            "SHA-256": r'\b[a-fA-F0-9]{64}\b',
            "SHA-384": r'\b[a-fA-F0-9]{96}\b',
            "SHA-512": r'\b[a-fA-F0-9]{128}\b'
        }

        algos_detectados = []
        texto_limpo = re.sub(r'[\u200b\u200e\u200f\x00]', '', texto_custodia)
        for algo, padrao in padroes.items():
            if re.search(padrao, texto_limpo):
                algos_detectados.append(algo)

        # =========================================================================
        # CAIXA PREENCHIDA, MAS NENHUM HASH DETECTADO
        # =========================================================================
        if not algos_detectados:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Aviso Forense - Validação de Custódia")

            fonte = msg_box.font()
            fonte.setPointSize(11)
            msg_box.setFont(fonte)

            msg_box.setText("<b>Nenhum hash criptográfico foi encontrado no texto inserido.</b>")
            msg_box.setInformativeText(
                "O campo de validação da cadeia de custódia não está vazio, mas o sistema não conseguiu "
                "localizar nenhum formato de hash válido (MD5, SHA-1, SHA-256, etc.) no seu conteúdo.\n\n"
                "Sendo assim, a validação automática não poderá ser realizada.\n\n"
                "Deseja prosseguir com a extração de hashes e/ou metadados sem validação de cadeia de custódia mesmo assim ou cancelar a operação?"
            )
            msg_box.setIcon(QMessageBox.Icon.Warning)

            btn_prosseguir = msg_box.addButton("Prosseguir com a extração", QMessageBox.ButtonRole.AcceptRole)
            btn_cancelar = msg_box.addButton("Cancelar", QMessageBox.ButtonRole.RejectRole)

            is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
            if is_dark:
                btn_prosseguir.setStyleSheet("""
                    QPushButton { padding: 6px 12px; font-weight: bold; background-color: #3c3f41; border: 1px solid #555555; border-radius: 4px; color: #ffffff; }
                    QPushButton:hover { background-color: #505355; border: 1px solid #777777; }
                    QPushButton:pressed { background-color: #2b2d2e; border: 1px solid #999999; }
                """)
                btn_cancelar.setStyleSheet("""
                    QPushButton { padding: 6px 12px; background-color: #2b2b2b; border: 1px solid #444444; border-radius: 4px; color: #ffffff; }
                    QPushButton:hover { background-color: #3b3b3b; border: 1px solid #666666; }
                    QPushButton:pressed { background-color: #1a1a1a; border: 1px solid #888888; }
                """)
            else:
                btn_prosseguir.setStyleSheet("""
                    QPushButton { padding: 6px 12px; font-weight: bold; background-color: #e0e0e0; border: 1px solid #cccccc; border-radius: 4px; color: #000000; }
                    QPushButton:hover { background-color: #d0d0d0; border: 1px solid #aaaaaa; }
                    QPushButton:pressed { background-color: #c0c0c0; border: 1px solid #888888; }
                """)
                btn_cancelar.setStyleSheet("""
                    QPushButton { padding: 6px 12px; background-color: #ffffff; border: 1px solid #cccccc; border-radius: 4px; color: #000000; }
                    QPushButton:hover { background-color: #eeeeee; border: 1px solid #bbbbbb; }
                    QPushButton:pressed { background-color: #dddddd; border: 1px solid #999999; }
                """)

            msg_box.exec()

            if msg_box.clickedButton() == btn_prosseguir:
                self.texto_referencia.clear()  # Limpa a caixa visualmente para não confundir o usuário
                return ""  # Retorna vazio para que o processo ignore a custódia
            else:
                return None # Cancela a operação

        # =========================================================================
        # FALTA SELECIONAR ALGUM HASH NA INTERFACE
        # =========================================================================
        if algos_detectados:
            marcados_atualmente = [algo for algo, chk in self.chk_hashes.items() if chk.isChecked() and algo != "CRC32"]
            faltando = set(algos_detectados) - set(marcados_atualmente)

            if faltando:
                algos_str = ", ".join(algos_detectados)
                msg_box = QMessageBox(self)
                msg_box.setWindowTitle("Inteligência Forense - Ajuste Necessário")

                fonte = msg_box.font()
                fonte.setPointSize(11)
                msg_box.setFont(fonte)

                msg_box.setText(
                    f"O texto de validação da custódia contém os seguintes hashes:<br><br><b>{algos_str}</b>")
                msg_box.setInformativeText(
                    "No momento, as caixas de seleção não estão configuradas para todos eles.\n"
                    "Esse ajuste é IMPRESCINDÍVEL para evitar inconsistências na validação.\n"
                    "Deseja ajustar automaticamente antes de iniciar a extração?"
                )
                msg_box.setIcon(QMessageBox.Icon.Warning)

                btn_auto = msg_box.addButton("Ajustar automaticamente", QMessageBox.ButtonRole.AcceptRole)
                btn_cancelar = msg_box.addButton("Cancelar extração", QMessageBox.ButtonRole.RejectRole)

                is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
                if is_dark:
                    btn_auto.setStyleSheet("""
                        QPushButton { padding: 6px 12px; font-weight: bold; background-color: #3c3f41; border: 1px solid #555555; border-radius: 4px; color: #ffffff; }
                        QPushButton:hover { background-color: #505355; border: 1px solid #777777; }
                        QPushButton:pressed { background-color: #2b2d2e; border: 1px solid #999999; }
                    """)
                    btn_cancelar.setStyleSheet("""
                        QPushButton { padding: 6px 12px; background-color: #2b2b2b; border: 1px solid #444444; border-radius: 4px; color: #ffffff; }
                        QPushButton:hover { background-color: #3b3b3b; border: 1px solid #666666; }
                        QPushButton:pressed { background-color: #1a1a1a; border: 1px solid #888888; }
                    """)
                else:
                    btn_auto.setStyleSheet("""
                        QPushButton { padding: 6px 12px; font-weight: bold; background-color: #e0e0e0; border: 1px solid #cccccc; border-radius: 4px; color: #000000; }
                        QPushButton:hover { background-color: #d0d0d0; border: 1px solid #aaaaaa; }
                        QPushButton:pressed { background-color: #c0c0c0; border: 1px solid #888888; }
                    """)
                    btn_cancelar.setStyleSheet("""
                        QPushButton { padding: 6px 12px; background-color: #ffffff; border: 1px solid #cccccc; border-radius: 4px; color: #000000; }
                        QPushButton:hover { background-color: #eeeeee; border: 1px solid #bbbbbb; }
                        QPushButton:pressed { background-color: #dddddd; border: 1px solid #999999; }
                    """)

                msg_box.exec()

                if msg_box.clickedButton() == btn_auto:
                    for algo, chk in self.chk_hashes.items():
                        if algo == "CRC32":
                            chk.setChecked(False)
                        else:
                            chk.setChecked(algo in algos_detectados)
                    self.salvar_estado_atual()
                    return texto_custodia
                else:
                    return None

        return texto_custodia

    def alternar_modo_escuro(self, ativado):
        app = QApplication.instance()  # Captura a instância global do aplicativo

        if ativado:
            # --- ESTILO MODO ESCURO ---
            estilo_global = """
                QWidget { background-color: #2b2b2b; color: #f0f0f0; }
                QPushButton { background-color: #3c3f41; border: 1px solid #555555; padding: 4px; border-radius: 4px; }
                QPushButton:hover { background-color: #4b4d4f; }
                QPushButton:pressed { background-color: #2b2b2b; }
                QPushButton:disabled { background-color: #2b2b2b; color: #666666; border: 1px solid #444444; }
                QCheckBox { color: #f0f0f0; }
                QComboBox { background-color: #3c3f41; color: #f0f0f0; border: 1px solid #555555; }
                QTextBrowser { background-color: #1e1e1e; color: #d4d4d4; border: 1px solid #555555; }
            """
            self.setStyleSheet(estilo_global)

            # Atualiza o estilo individual de cada QGroupBox para a cor cinza-clara do Modo Escuro
            estilo_caixas_escuro = """
                QGroupBox { border: 1px solid #555555; margin-top: 10px; border-radius: 3px; padding-top: 5px; }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; color: #f0f0f0; }
            """
            if hasattr(self, 'grupo_wb'):
                self.grupo_wb.setStyleSheet(estilo_caixas_escuro)

            self.grupo_topo.setStyleSheet(estilo_caixas_escuro)
            self.grupo_controles.setStyleSheet(estilo_caixas_escuro)

            # Revalida o botão do Write-Blocker para manter o aviso vermelho ou adotar a cor tema correta
            if hasattr(self, 'atualizar_ui_write_blocker'):
                self.atualizar_ui_write_blocker()
            if hasattr(self, 'grupo_validacao'):
                self.grupo_validacao.setStyleSheet(estilo_caixas_escuro)

            if hasattr(self, 'grupo_saida'):
                self.grupo_saida.setStyleSheet(estilo_caixas_escuro)

            # Altera a folha de estilos das Tooltips globais para o modo escuro
            if isinstance(app, QApplication):
                app.setStyleSheet("""
                    QToolTip {
                        background-color: #3c3f41;
                        color: #ffffff;
                        border: 1px solid #555555;
                        padding: 2px;
                        font-size: 10pt;
                    }
                """)

            # Substituindo os componentes que tinham cores hardcoded
            self.texto_saida.setStyleSheet(
                "background-color: #1e1e1e; color: #d4d4d4; font-family: Consolas; font-size: 10pt; border: 1px solid #555555;")
            self.btn_unidade_raw.setStyleSheet("""
                QPushButton { 
                    font-weight: bold; 
                    color: #ff6666; 
                    background-color: #3c3f41; 
                    border: 1px solid #ff6666;
                    border-radius: 4px;
                    padding: 4px;
                }
                QPushButton:hover { background-color: #4b4d4f; }
                QPushButton:pressed { background-color: #2b2b2b; }
                QPushButton:disabled { color: #666666; background-color: #2b2b2b; border: 1px solid #444444; }
            """)
            self.texto_referencia.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; border: 1px solid #555555;")

        else:
            # --- ESTILO MODO CLARO (Padrão) ---
            self.setStyleSheet("")

            # Restaura o estilo individual de cada QGroupBox para a cor preta do Modo Claro
            estilo_caixas_claro = """
                QGroupBox { border: 1px solid #cccccc; margin-top: 10px; border-radius: 3px; padding-top: 5px; }
                QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; color: #111111; }
            """
            if hasattr(self, 'grupo_wb'):
                self.grupo_wb.setStyleSheet(estilo_caixas_claro)
            self.grupo_topo.setStyleSheet(estilo_caixas_claro)
            self.grupo_controles.setStyleSheet(estilo_caixas_claro)

            if hasattr(self, 'atualizar_ui_write_blocker'):
                self.atualizar_ui_write_blocker()
            if hasattr(self, 'grupo_validacao'):
                self.grupo_validacao.setStyleSheet(estilo_caixas_claro)

            if hasattr(self, 'grupo_saida'):
                self.grupo_saida.setStyleSheet(estilo_caixas_claro)

            # Restaura a folha de estilos das Tooltips globais para o modo claro
            if isinstance(app, QApplication):
                app.setStyleSheet("""
                    QToolTip {
                        background-color: #ffffff;
                        color: #000000;
                        border: 1px solid #cccccc;
                        padding: 2px;
                        font-size: 10pt;
                    }
                """)

            # Restaurando os componentes que tinham cores hardcoded originais
            self.texto_saida.setStyleSheet(
                "background-color: #f4f4f4; color: #111111; font-family: Consolas; font-size: 10pt;")
            self.btn_unidade_raw.setStyleSheet("""
                QPushButton { font-weight: bold; color: #800000; background-color: #e6e6e6; border: 1px solid #cccccc; border-radius: 4px; padding: 4px; }
                QPushButton:hover { background-color: #d4d4d4; border: 1px solid #b3b3b3; }
                QPushButton:pressed { background-color: #c5c5c5; border: 1px solid #999999; }
                QPushButton:disabled { color: #999999; background-color: #f0f0f0; border: 1px solid #cccccc; }
            """)
            self.texto_referencia.setStyleSheet("")

        # --- Atualiza dinamicamente o aviso em vermelho da Tooltip do CRC32 ---
        if hasattr(self, "chk_hashes") and "CRC32" in self.chk_hashes:
            cor_alerta_crc32 = "#ff6666" if ativado else "#990000"
            tooltip_crc32 = (
                "<p><b>CRC32:</b> Verificação de redundância (Não Criptográfico).</p>"
                "<ul><li><b>Segurança:</b> Nula.</li>"
                "<li><b>Colisão:</b> Altíssima.</li>"
                "<li><b>Uso:</b> Inseguro para evidências. Útil apenas para detecção rápida de corrupção. <br><br>"
                f"<span style='color: {cor_alerta_crc32};'><b>⚠️ Nota Pericial:</b> Para evitar falsos positivos, o CRC32 é "
                "intencionalmente ignorado na conferência automática da Cadeia de Custódia.</span></li></ul>"
            )
            self.chk_hashes["CRC32"].setToolTip(tooltip_crc32)

        if hasattr(self, 'atualizar_tooltip_wb'):
            self.atualizar_tooltip_wb()

    def _garantir_exclusividade_basico(self, checked):
        if checked:
            self.chk_metadados_raw.setChecked(False)

    def _garantir_exclusividade_raw(self, checked):
        if checked:
            self.chk_metadados.setChecked(False)

    def checar_atualizacoes(self):
        """Checa na API do GitHub se há uma nova Release publicada e obtém o link do ZIP."""
        url = f"https://api.github.com/repos/{USUARIO}/{REPOSITORIO}/releases/latest"

        def _worker():
            try:
                import urllib.request
                import json
                import ssl  # <-- Importação necessária

                # Cria o contexto para contornar bloqueios de proxy/SSL corporativo
                contexto_ssl = ssl._create_unverified_context()

                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})

                # Aumentei o timeout para 10s e adicionei o contexto SSL
                with urllib.request.urlopen(req, timeout=10, context=contexto_ssl) as response:
                    dados = json.loads(response.read().decode('utf-8'))

                versao_github_bruta = dados.get('tag_name', '')
                url_download_pagina = dados.get('html_url', LINK_GITHUB)
                notas_lancamento = dados.get('body', 'Sem notas de lançamento disponíveis.')

                # Busca o link direto do arquivo ZIP nos anexos da release
                url_download_zip = ""
                for asset in dados.get('assets', []):
                    if asset.get('name', '').endswith('.zip'):
                        url_download_zip = asset.get('browser_download_url', '')
                        break

                match_gh = re.search(r'(\d+\.\d+\.\d+)', versao_github_bruta)
                match_local = re.search(r'(\d+\.\d+\.\d+)', VERSAO_APP)

                if match_gh and match_local:
                    str_gh = match_gh.group(1)
                    str_local = match_local.group(1)
                    tup_gh = tuple(map(int, str_gh.split('.')))
                    tup_local = tuple(map(int, str_local.split('.')))

                    if tup_gh > tup_local:
                        self.sinal_atualizacao.emit(versao_github_bruta, url_download_pagina, notas_lancamento,
                                                    url_download_zip)

            except Exception as e:
                # Opcional: printar o erro caso o DEBUG_MESSAGES esteja ativado
                if DEBUG_MESSAGES:
                    print(f"[DEBUG] Falha ao checar atualização: {e}")
                pass

        import threading
        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    def _exibir_alerta_atualizacao(self, nova_versao, link_pagina, notas_lancamento, url_zip):
        # Salva o link e a versão para usarmos depois que o usuário clicar no botão
        self.url_atualizacao_pendente = url_zip if url_zip else link_pagina
        self.versao_atualizacao_pendente = nova_versao
        self.tem_atualizacao_zip = bool(url_zip)

        # Adicionado o botão de ler as notas ao lado da atualização
        if self.tem_atualizacao_zip:
            botao_acao = (
                f"<a href='atualizar_agora' style='color: #0056b3; text-decoration: none; font-weight: bold; font-size: 11pt;'>"
                f"✨ CLIQUE AQUI PARA ATUALIZAR AUTOMATICAMENTE"
                f"</a>"
                f"&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;"
                f"<a href='{link_pagina}' style='color: #333333; text-decoration: underline; font-size: 11pt;'>"
                f"📄 Ler notas de lançamento no GitHub"
                f"</a>"
            )
        else:
            botao_acao = (
                f"<a href='{link_pagina}' style='color: #0056b3; text-decoration: none; font-weight: bold; font-size: 11pt;'>"
                f"📥 BAIXAR ATUALIZAÇÃO MANUALMENTE (e ler notas da versão)"
                f"</a>"
            )

        alerta_html = (
            f"<div style='background-color: #fff3cd; border: 1px solid #ffeeba; padding: 12px; border-radius: 5px; margin-bottom: 5px;'>"
            f"<span style='color: #856404; font-size: 11pt;'>"
            f"<b>⚠️ Nova atualização disponível!</b> A versão <b>{nova_versao}</b> foi lançada! "
            f"(Você está usando a v.{VERSAO_APP}).<br><br>"
            f"{botao_acao}"
            f"</span>"
            f"</div>"
        )

        import html
        notas = html.escape(notas_lancamento).replace('\r\n', '\n')
        while '\n\n\n' in notas:
            notas = notas.replace('\n\n\n', '\n\n')

        notas = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', notas)
        notas = re.sub(r'^- (.*)', r'• \1', notas, flags=re.MULTILINE)
        notas = re.sub(r'^#+ (.*)', r'<b>\1</b>', notas, flags=re.MULTILINE)

        # NOVIDADE: Ajustamos o texto caso a nota seja muito grande
        if len(notas) > 1200:
            notas = notas[:1200] + "\n\n... (Texto longo: Clique em 'Ler notas de lançamento' na barra amarela para ver na íntegra no GitHub)."

        notas_formatadas = notas.replace('\n', '<br>')

        # Removidas as variáveis estáticas de cor que causavam quebra de contraste ao alternar o tema.
        # Sem as cores fixas no estilo inline, o HTML herdará dinamicamente o esquema ativo do QToolTip.
        tooltip_html = (
            f"<div style='width: 650px; font-size: 10pt; line-height: 1.2; font-family: Consolas, monospace; padding: 5px;'>"
            f"<span style='font-size: 11pt;'><b>O que há de novo na versão {nova_versao}:</b></span><hr>"
            f"{notas_formatadas}"
            f"</div>"
        )

        self.lbl_alerta_versao.setText(alerta_html)
        self.lbl_alerta_versao.show()

        # Guarda o texto da tooltip na própria label
        self.lbl_alerta_versao.custom_tooltip_text = tooltip_html
        self.lbl_alerta_versao.installEventFilter(self)

    def atualizar_tempo_total(self):
        if not self.processando or self.total_bytes_processar == 0:
            return

        decorrido = time.time() - self.tempo_inicio_total

        # Formatação do tempo decorrido
        horas_d, rem_d = divmod(decorrido, 3600)
        mins_d, segs_d = divmod(rem_d, 60)
        str_decorrido = f"{int(horas_d):02d}:{int(mins_d):02d}:{int(segs_d):02d}"

        # Cálculo do tempo restante baseado nos BYTES processados (alta precisão)
        if self.bytes_processados_total > 0:
            bytes_por_segundo = self.bytes_processados_total / decorrido
            bytes_restantes = self.total_bytes_processar - self.bytes_processados_total

            # Evita divisão por zero caso a leitura trave
            restante = bytes_restantes / bytes_por_segundo if bytes_por_segundo > 0 else 0

            horas_r, rem_r = divmod(restante, 3600)
            mins_r, segs_r = divmod(rem_r, 60)
            str_restante = f"{int(horas_r):02d}:{int(mins_r):02d}:{int(segs_r):02d}"
        else:
            str_restante = "Calculando..."

        fmt_processados = formatar_bytes_dinamico(self.bytes_processados_total)
        fmt_total = formatar_bytes_dinamico(self.total_bytes_processar)

        self.lbl_progresso_total.setText(
            f"Progresso Total ({fmt_processados} / {fmt_total}) - Decorrido: {str_decorrido} | Restante: {str_restante}"
        )

    def _tratar_clique_atualizacao(self, link):
        """Intercepta o clique na barra amarela. Se for o comando de atualizar, roda a rotina."""
        if link == "atualizar_agora" and hasattr(self, 'url_atualizacao_pendente'):

            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Confirmar Atualização")

            fonte = msg_box.font()
            fonte.setPointSize(11)
            msg_box.setFont(fonte)

            msg_box.setText("<b>Deseja preparar a atualização automática agora?</b>")
            msg_box.setInformativeText(
                "O programa baixará a nova versão e criará uma nova pasta ao lado da atual, "
                "para evitar bloqueios de antivírus.\n\n"
                "⚠️ ATENÇÃO: Quaisquer resultados de extração que estiverem na tela serão apagados. "
                "Certifique-se de ter salvo seu relatório antes de prosseguir.\n\n"
                "Deseja continuar?"
            )
            msg_box.setIcon(QMessageBox.Icon.Warning)

            btn_sim = msg_box.addButton("Sim, atualizar", QMessageBox.ButtonRole.AcceptRole)
            btn_nao = msg_box.addButton("Não, cancelar", QMessageBox.ButtonRole.RejectRole)

            is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
            if is_dark:
                btn_sim.setStyleSheet(
                    "QPushButton { padding: 6px 12px; font-weight: bold; background-color: #3c3f41; border: 1px solid #555555; border-radius: 4px; color: #ffffff; } QPushButton:hover { background-color: #505355; border: 1px solid #777777; }")
                btn_nao.setStyleSheet(
                    "QPushButton { padding: 6px 12px; background-color: #2b2b2b; border: 1px solid #444444; border-radius: 4px; color: #ffffff; } QPushButton:hover { background-color: #3b3b3b; border: 1px solid #666666; }")
            else:
                btn_sim.setStyleSheet(
                    "QPushButton { padding: 6px 12px; font-weight: bold; background-color: #e0e0e0; border: 1px solid #cccccc; border-radius: 4px; color: #000000; } QPushButton:hover { background-color: #d0d0d0; border: 1px solid #aaaaaa; }")
                btn_nao.setStyleSheet(
                    "QPushButton { padding: 6px 12px; background-color: #ffffff; border: 1px solid #cccccc; border-radius: 4px; color: #000000; } QPushButton:hover { background-color: #eeeeee; border: 1px solid #bbbbbb; }")

            msg_box.exec()

            if msg_box.clickedButton() == btn_sim:
                # Aqui está a mágica: usamos a variável que salvamos no Passo 1
                self.atualizar_programa_automaticamente(
                    self.url_atualizacao_pendente,
                    self.versao_atualizacao_pendente
                )

        else:
            import webbrowser
            webbrowser.open(link)

    def atualizar_programa_automaticamente(self, url_download_zip, nova_versao):
        """Baixa o ZIP da release e extrai em uma nova pasta ao lado da atual (Side-by-Side)."""

        # Inicializa as variáveis para o bloco de limpeza (evita alertas da IDE)
        caminho_zip = None
        pasta_extracao = None

        self.texto_saida.clear()
        self.travar_interface()

        self.texto_saida.append("=======================================================")
        self.texto_saida.append("⏳ PREPARANDO NOVA VERSÃO... POR FAVOR, AGUARDE.")
        self.texto_saida.append("=======================================================\n")

        try:
            # Descobre a pasta onde a versão atual está guardada
            if is_running_compiled():
                pasta_atual_programa = os.path.dirname(obter_caminho_exe())
            else:
                pasta_atual_programa = os.path.dirname(os.path.abspath(__file__))

            diretorio_pai = os.path.dirname(pasta_atual_programa)

            # Formata o nome da nova pasta baseada na versão do GitHub
            # 1. Limpa a versão que vem do GitHub para garantir que teremos só os números (ex: "5.0.1")
            nova_versao_numeros = nova_versao.lower().replace('v', '').strip()
            if nova_versao_numeros.startswith('.'):  # Remove ponto extra se vier "v.5.0.1"
                nova_versao_numeros = nova_versao_numeros[1:]

            # 2. Monta o nome exato no seu padrão
            nome_nova_pasta = f"Extrator_ERS-IC-SP-NIC_v{nova_versao_numeros}"

            pasta_extracao = os.path.join(diretorio_pai, nome_nova_pasta)

            pasta_temp = tempfile.gettempdir()
            caminho_zip = os.path.join(pasta_temp, f"extrator_update_{nova_versao_numeros}.zip")

            # 1. Baixar
            self.texto_saida.append("📥 1/3 - Baixando a nova versão do GitHub...")
            QApplication.processEvents()

            import urllib.request
            import ssl
            contexto_ssl = ssl._create_unverified_context()  # Evita erros de proxy em redes policiais

            req = urllib.request.Request(url_download_zip, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, context=contexto_ssl) as response, open(caminho_zip, 'wb') as out_file:
                out_file.write(response.read())

            # 2. Descompactar
            self.texto_saida.append(f"📦 2/3 - Extraindo arquivos para a nova pasta:\n   ↳ {pasta_extracao}")
            QApplication.processEvents()

            # --- 1. PREPARAÇÃO DO DIRETÓRIO (DELEÇÃO SE EXISTIR) ---
            if os.path.exists(pasta_extracao):
                import shutil
                try:
                    # Tenta excluir a pasta da atualização anterior sem silenciar erros
                    shutil.rmtree(pasta_extracao)
                except Exception as e:
                    # Se falhar (ex: pasta aberta no Explorer, arquivo em uso), alerta e aborta
                    msg_erro = QMessageBox(self)
                    msg_erro.setWindowTitle("Erro na Atualização")
                    msg_erro.setIcon(QMessageBox.Icon.Critical)
                    msg_erro.setText(
                        "<span style='font-size: 11pt;'><b>Falha ao preparar o diretório de destino.</b></span>")
                    msg_erro.setInformativeText(
                        f"<p style='line-height: 1.4;'>"
                        f"Não foi possível limpar a pasta de atualização anterior:<br><i>{pasta_extracao}</i><br><br>"
                        "<b>Motivo Provável:</b> A pasta está aberta no Windows Explorer ou o novo extrator já está em execução em segundo plano.<br><br>"
                        "<b>Solução:</b> Feche todas as janelas do Windows Explorer, certifique-se de que a nova versão não está rodando e clique em Atualizar novamente.<br><br>"
                        f"<span style='font-size: 9pt; color: #888888;'>Detalhe Técnico: {str(e)}</span>"
                        f"</p>"
                    )

                    is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
                    if is_dark:
                        msg_erro.setStyleSheet(
                            "QMessageBox { background-color: #2b2b2b; color: #f0f0f0; } QLabel { color: #f0f0f0; } QPushButton { background-color: #3c3f41; color: #f0f0f0; padding: 6px 15px; }")

                    msg_erro.exec()
                    self.texto_saida.append(
                        "\n❌ Atualização abortada: Diretório de destino bloqueado pelo Windows.")
                    self.destravar_interface()  # Destrava a tela para o usuário
                    return  # 🛑 ABORTA A FUNÇÃO AQUI

            # --- 2. EXTRAÇÃO DO ARQUIVO ZIP ---
            try:
                import zipfile
                with zipfile.ZipFile(caminho_zip, 'r') as zip_ref:
                    zip_ref.extractall(pasta_extracao)

                # Apaga o zip baixado após extrair com sucesso
                os.remove(caminho_zip)

            except Exception as e:
                # Se a extração falhar (ex: falta de permissão, bloqueio de antivírus), alerta e aborta
                msg_erro = QMessageBox(self)
                msg_erro.setWindowTitle("Erro na Descompactação")
                msg_erro.setIcon(QMessageBox.Icon.Critical)
                msg_erro.setText(
                    "<span style='font-size: 11pt;'><b>Falha ao descompactar os arquivos da atualização.</b></span>")
                msg_erro.setInformativeText(
                    f"<p style='line-height: 1.4;'>"
                    f"Ocorreu um erro ao tentar salvar a nova versão na pasta:<br><i>{pasta_extracao}</i><br><br>"
                    "<b>Motivo Provável:</b> Bloqueio de permissão de escrita pelo Windows, falta de espaço em disco ou interferência do Antivírus.<br><br>"
                    "<b>Solução:</b> Verifique as permissões da pasta onde o extrator está instalado e tente novamente.<br><br>"
                    f"<span style='font-size: 9pt; color: #888888;'>Detalhe Técnico: {str(e)}</span>"
                    f"</p>"
                )

                is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
                if is_dark:
                    msg_erro.setStyleSheet(
                        "QMessageBox { background-color: #2b2b2b; color: #f0f0f0; } QLabel { color: #f0f0f0; } QPushButton { background-color: #3c3f41; color: #f0f0f0; padding: 6px 15px; }")

                msg_erro.exec()
                self.texto_saida.append("\n❌ Atualização abortada: Falha na gravação/descompactação dos arquivos.")
                self.destravar_interface()  # Destrava a tela para o usuário
                return  # 🛑 ABORTA A FUNÇÃO AQUI

            # 3. Conclusão
            self.texto_saida.append("\n✅ 3/3 - ATUALIZAÇÃO CONCLUÍDA COM SUCESSO!")
            QApplication.processEvents()

            # --- AVISO BLOQUEANTE ANTES DE FECHAR COM ORIENTAÇÃO DE ATALHOS ---
            msg_conclusao = QMessageBox(self)
            msg_conclusao.setWindowTitle("Atualização Concluída")

            # Título levemente maior
            msg_conclusao.setText("<span style='font-size: 13pt;'><b>O extrator foi atualizado com sucesso!</b></span>")

            msg_conclusao.setInformativeText(
                "<p style='font-size: 11pt; line-height: 1.4;'>"
                "A nova versão foi salva em uma pasta separada ao lado da atual, preservando sua segurança.<br><br>"
                "Ao clicar em 'OK', o Windows Explorer será aberto mostrando o diretório com o novo <b>extrator_hashes_metadados.exe</b>. "
                "Para evitar confusão e liberar espaço no disco, recomendamos que você apague a pasta da versão antiga manualmente.<br><br>"
                "⚠️ <b>IMPORTANTE:</b> Como o caminho do programa mudou, lembre-se de <b>refazer seus atalhos</b> na Área de Trabalho e/ou "
                "<b>vincular novamente o ícone do extrator</b> na Barra de Tarefas do Windows se costuma utilizá-lo fixado lá.<br><br>"
                "O extrator antigo será encerrado agora."
                "</p>"
            )
            msg_conclusao.setIcon(QMessageBox.Icon.Information)

            # Estilos CSS para forçar a largura mínima da janela (min-width) e formatar o botão
            is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
            if is_dark:
                msg_conclusao.setStyleSheet(
                    "QMessageBox { background-color: #2b2b2b; color: #f0f0f0; min-width: 550px; } "
                    "QLabel { color: #f0f0f0; } "
                    "QPushButton { background-color: #3c3f41; color: #f0f0f0; padding: 6px 25px; font-weight: bold; font-size: 11pt; border: 1px solid #555555; border-radius: 4px; }"
                )
            else:
                msg_conclusao.setStyleSheet(
                    "QMessageBox { min-width: 550px; } "
                    "QLabel { color: #111111; } "
                    "QPushButton { background-color: #f0f0f0; color: #111111; padding: 6px 25px; font-weight: bold; font-size: 11pt; border: 1px solid #cccccc; border-radius: 4px; }"
                )

            msg_conclusao.exec()  # 🛑 Pausa a execução aqui até o usuário clicar em "OK"
            # -----------------------------------------------------------------

            # Abre a pasta nova na cara do usuário para ele ver o arquivo
            if os.name == 'nt':
                os.startfile(pasta_extracao)

            # Fecha a versão velha
            QApplication.quit()

        except Exception as e:
            self.texto_saida.append(f"\n❌ ERRO DURANTE A ATUALIZAÇÃO: {e}")
            self.texto_saida.append("   ↳ A operação foi cancelada. O programa atual não foi afetado.")
            self.texto_saida.append("   ↳ Tente usar o botão de [BAIXAR ATUALIZAÇÃO MANUALMENTE].")

            # ==========================================
            # TRATAMENTO DE FALHAS (FAZENDO A LIMPEZA)
            # ==========================================

            # 1. Se o ZIP corrompido ficou no Temp (download pela metade), apaga ele:
            if caminho_zip and os.path.exists(caminho_zip):
                try:
                    os.remove(caminho_zip)
                except:
                    pass

            # 2. Se a pasta nova ficou pela metade (falha na extração), apaga ela:
            if pasta_extracao and os.path.exists(pasta_extracao):
                try:
                    import shutil
                    shutil.rmtree(pasta_extracao, ignore_errors=True)
                except:
                    pass

            # Devolve o controle para o perito
            self.destravar_interface()

    def exportar_codigo_fonte(self):
        """Permite que o usuário salve uma cópia do script para auditoria forense"""
        try:
            # Se estiver rodando como .py, usa o __file__
            if sys.argv[0].endswith('.py'):
                caminho_origem = os.path.abspath(__file__)
            else:
                # No Nuitka Standalone, o arquivo .py estará na raiz da pasta do .exe
                diretorio_exe = os.path.dirname(os.path.abspath(sys.executable))
                caminho_origem = os.path.join(diretorio_exe, "extrator_hashes_metadados.py")

            if not os.path.exists(caminho_origem):
                QMessageBox.warning(self, "Aviso de Auditoria",
                    "O arquivo de código-fonte não foi localizado no pacote.\n"
                    "Certifique-se de que o arquivo 'extrator_hashes_metadados.py' está na pasta do programa.")
                return

            opcoes_salvar = QFileDialog.Option.DontUseNativeDialog
            caminho_destino, _ = QFileDialog.getSaveFileName(
                self, "Exportar Código Fonte para Auditoria",
                "extrator_hashes_metadados_auditoria.py", "Python Script (*.py)",
                options=opcoes_salvar
            )

            if caminho_destino:
                import shutil
                shutil.copy(caminho_origem, caminho_destino)
                QMessageBox.information(self, "Sucesso", "Código-fonte exportado com sucesso para auditoria.")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Falha ao exportar código: {e}")

    def _ativar_modo_admin_visual(self):
        self._titulo_original = self.windowTitle()
        self.setWindowTitle(self._titulo_original + "  |  MODO ADMINISTRADOR ATIVADO")

        # Define um ObjectName para a janela principal se ela ainda não tiver
        self.setObjectName("MainWindow")

        # Estilo geral da janela (Fundo vermelho e letras brancas para textos soltos)
        # Corrigido fundo dos botões e contraste das caixas de seleção
        estilo_admin = """
                            #MainWindow { background-color: #4a0000; }
                            #MainWindow QLabel, #MainWindow QGroupBox { color: #f0f0f0; }
    
                            #MainWindow QCheckBox { color: #f0f0f0; }
                            #MainWindow QCheckBox::indicator { background-color: #ffffff; border: 1px solid #cccccc; width: 13px; height: 13px; }
                            #MainWindow QCheckBox::indicator:checked { background-color: #cc0000; border: 1px solid #ff9999; }
    
                            #MainWindow QPushButton { 
                                background-color: #7a0000; 
                                color: #ffffff; 
                                border: 1px solid #a30000;
                                padding: 4px;
                                border-radius: 4px;
                            }
                            #MainWindow QPushButton:hover { background-color: #990000; }
                            #MainWindow QPushButton:pressed { background-color: #5a0000; border: 1px solid #800000; } /* <-- ADICIONADO AQUI */
                            #MainWindow QPushButton:disabled { 
                                background-color: #330000; 
                                color: #888888; 
                                border: 1px solid #550000; 
                            }
    
                            QProgressBar {
                                border: 1px solid #7a0000;
                                background-color: #2a0000;
                                text-align: center;
                                color: #ffffff;
                                font-weight: bold;
                                border-radius: 4px;
                            }
                            QProgressBar::chunk {
                                background-color: #cc0000;
                            }
                        """
        self.setStyleSheet(estilo_admin)

        # Trata a caixa de texto grande (QTextEdit) individualmente para evitar conflito de prioridade de CSS
        self._estilo_texto_original = self.texto_saida.styleSheet()
        self.texto_saida.setStyleSheet(
            "background-color: #330000; color: #ffffff; font-family: Consolas; font-size: 10pt; border: 1px solid #7a0000;")

    def _desativar_modo_admin_visual(self):
        if hasattr(self, "_titulo_original"):
            self.setWindowTitle(self._titulo_original)

        # SE O MODO ESCURO ESTIVER ATIVADO, VOLTA PRA ELE. SENÃO, VOLTA PRO CLARO.
        if hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked():
            self.alternar_modo_escuro(True)
        else:
            self.setStyleSheet("")
            if hasattr(self, "_estilo_texto_original"):
                self.texto_saida.setStyleSheet(self._estilo_texto_original)

        # Re-aplica o estilo padronizado com texto centralizado nas barras
        if hasattr(self, "estilo_barra_padrao"):
            self.barra_arquivo.setStyleSheet(self.estilo_barra_padrao)
            self.barra_total.setStyleSheet(self.estilo_barra_padrao)

        if hasattr(self, "_estilo_texto_original"):
            self.texto_saida.setStyleSheet(self._estilo_texto_original)

    def _temp_paths_raw(self):
        base = os.path.join(tempfile.gettempdir(), "ERS_IC_NIC_RAW_" + uuid.uuid4().hex)
        os.makedirs(base, exist_ok=True)
        out_json = os.path.join(base, "resultado.json")
        progress_json = os.path.join(base, "progresso.json")
        cancel_flag = os.path.join(base, "CANCELAR.flag")
        return out_json, progress_json, cancel_flag

    def _listar_unidades_windows(self):
        import shutil  # Certifique-se de que o import shutil está no topo do seu script

        def formatar_bytes(tamanho_em_bytes):
            try:
                tamanho = float(tamanho_em_bytes)
                for unidade in ['B', 'KB', 'MB', 'GB', 'TB']:
                    if tamanho < 1024.0:
                        return f"{tamanho:.1f} {unidade}"
                    tamanho /= 1024.0
                return f"{tamanho:.1f} PB"
            except (ValueError, TypeError):
                return "Tamanho Desconhecido"

        # 1. Lista A:\ a Z:\ presentes (Volumes Lógicos Montados)
        drives_mask = kernel32.GetLogicalDrives()
        out = []
        for i in range(26):
            if drives_mask & (1 << i):
                letter = chr(ord("A") + i)
                root = f"{letter}:\\"
                dtype = get_drive_type(root)

                # Tenta obter a capacidade, falha silenciosamente se for formato RAW/Inacessível
                capacidade_str = "Tamanho Desconhecido"
                try:
                    uso = shutil.disk_usage(root)
                    capacidade_str = formatar_bytes(uso.total)
                except Exception:
                    pass

                out.append((letter, root, dtype, "LOGICO", "", capacidade_str))

        # 2. Lista os Discos Físicos (PhysicalDrives) via WMIC
        try:
            # Usamos o formato de tabela padrão pois é mais fácil isolar a última coluna (Size)
            resultado = subprocess.run(
                ["wmic", "diskdrive", "get", "deviceid,model,size"],
                capture_output=True, text=True, creationflags=0x08000000
            )
            linhas = resultado.stdout.strip().splitlines()

            for linha in linhas[1:]:  # Pula o cabeçalho (DeviceID, Model, Size)
                linha = linha.strip()
                if not linha: continue

                partes = linha.split()
                if len(partes) >= 3:
                    device_id = partes[0].strip()  # Primeiro elemento é o DeviceID
                    size_bytes = partes[-1].strip()  # Último elemento é o Size
                    model = " ".join(partes[1:-1]).strip()  # Tudo no meio é o Modelo

                    if device_id.upper().startswith("\\\\.\\PHYSICALDRIVE"):
                        num = device_id.upper().replace("\\\\.\\PHYSICALDRIVE", "")
                        capacidade_str = formatar_bytes(size_bytes)
                        out.append((f"Disco {num}", device_id, DRIVE_FIXED, "FISICO", model, capacidade_str))
        except Exception:
            pass

        return out

    def _tipo_unidade_texto(self, dtype: int) -> str:
        return {
            DRIVE_REMOVABLE: "Removível (Pendrive/SD)",
            DRIVE_FIXED: "Fixo (HD/SSD)",
            DRIVE_CDROM: "CD/DVD",
            DRIVE_REMOTE: "Rede",
        }.get(dtype, "Desconhecido")

    def selecionar_unidade_raw(self, unidade_pre_selecionada=None):
        if self.processando:
            return

        if os.name != "nt":
            QMessageBox.warning(self, "Indisponível", "Hash RAW só está disponível no Windows.")
            return

        unidades = self._listar_unidades_windows()
        # filtra coisas inúteis
        unidades = [u for u in unidades if u[2] in (DRIVE_REMOVABLE, DRIVE_FIXED, DRIVE_CDROM)]

        # ======================================================================
        # FILTRAR APENAS A UNIDADE ARRASTADA E SEU HARDWARE
        # ======================================================================
        if unidade_pre_selecionada:
            unidades_filtradas = []
            fisicos_associados = []

            # 1. Tenta descobrir quais discos físicos (PhysicalDrives) pertencem a esta letra lógica
            try:
                # Transforma "D:\" em "\\.\D:" para a API de baixo nível do Windows
                volume_dev = drive_root_to_volume_device(unidade_pre_selecionada)
                indices_fisicos = volume_to_physical_drives(volume_dev)
                # Monta a string no formato exato que a lista do Windows devolve
                fisicos_associados = [f"\\\\.\\PHYSICALDRIVE{idx}".upper() for idx in indices_fisicos]
            except Exception:
                pass  # Se falhar (ex: Mídia Óptica), mantém vazio e exibirá apenas o volume lógico

            # 2. Filtra a lista original para manter apenas o Alvo e seu Hardware correspondente
            for u in unidades:
                nome_curto, root, dtype, nivel, modelo, capacidade = u

                # Mantém se for o volume lógico arrastado
                if nivel == "LOGICO" and root.upper() == unidade_pre_selecionada.upper():
                    unidades_filtradas.append(u)
                # Mantém se for o disco físico (hardware) que contém aquele volume
                elif nivel == "FISICO" and root.upper() in fisicos_associados:
                    unidades_filtradas.append(u)

            unidades = unidades_filtradas
        # ======================================================================

        if not unidades:
            QMessageBox.information(self, "Unidades", "Nenhuma unidade removível/fixa/CD detectada.")
            return

        # Dialog simples com combo configurado com o novo padrão visual
        dialog = QDialog(self)
        dialog.setWindowTitle("Selecionar unidade para HASH RAW")
        dialog.setMinimumWidth(800)  # Janela mais larga para melhor leitura das mídias

        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        lbl_unidade = QLabel("Escolha a unidade para análise:")
        lbl_unidade.setStyleSheet("font-size: 12pt; font-weight: bold;")
        layout.addWidget(lbl_unidade)

        # Importações injetadas localmente para evitar erros
        from PySide6.QtWidgets import QListWidget, QListWidgetItem
        from PySide6.QtCore import Qt

        lista_unidades = QListWidget()

        # O QListWidget respeita perfeitamente o CSS e adiciona a barra de rolagem sozinho
        lista_unidades.setStyleSheet("""
                    QListWidget {
                        font-size: 11pt; 
                        padding: 5px; 
                        border: 1px solid #cccccc; 
                        border-radius: 4px;
                        outline: none; /* Remove a linha pontilhada nativa de foco */
                    }
                    QListWidget::item {
                        padding: 10px; /* Itens bem espaçados para clique fácil */
                        border-bottom: 1px solid #eeeeee;
                    }
                    QListWidget::item:selected {
                        background-color: #0078d7; /* Azul do Windows */
                        color: white;
                        font-weight: bold;
                    }
                """)

        # Define uma altura mínima para acomodar cerca de 6 a 7 itens,
        # mas permite que a lista expanda livremente caso o usuário redimensione a janela.
        lista_unidades.setMinimumHeight(260)

        # Preenche a lista com as unidades
        for indice, (nome_curto, root, dtype, nivel, modelo, capacidade) in enumerate(unidades):
            if nivel == "FISICO":
                texto_exibicao = f"HARDWARE DIRETO: {root} [{capacidade}]  -  {modelo}"
            else:
                texto_exibicao = f"VOLUME LÓGICO: {root} [{capacidade}]  -  {self._tipo_unidade_texto(dtype)}"

            # Cria o item visual
            item = QListWidgetItem(texto_exibicao)

            # Esconde os dados em background na variável "UserRole" do item
            item.setData(Qt.ItemDataRole.UserRole, (nome_curto, root, dtype, nivel))
            lista_unidades.addItem(item)

            # Lógica para Drag & Drop (Pré-seleção)
            if unidade_pre_selecionada and root.upper() == unidade_pre_selecionada.upper():
                item.setSelected(True)
                lista_unidades.setCurrentItem(item)

        # Se nada foi pré-selecionado, força a seleção no primeiro item por padrão
        if not lista_unidades.currentItem() and lista_unidades.count() > 0:
            lista_unidades.setCurrentRow(0)

        layout.addWidget(lista_unidades)

        layout.addSpacing(5)

        btns = QHBoxLayout()
        btn_ok = QPushButton("OK")
        btn_cancel = QPushButton("Cancelar")

        estilo_botoes_unidade = "font-size: 11pt; font-weight: bold; padding: 6px;"
        btn_ok.setStyleSheet(estilo_botoes_unidade)
        btn_cancel.setStyleSheet(estilo_botoes_unidade)
        btn_ok.setMinimumWidth(110)
        btn_cancel.setMinimumWidth(110)

        # Permite dar duplo clique direto na lista para prosseguir rapidamente
        lista_unidades.itemDoubleClicked.connect(dialog.accept)

        btn_ok.clicked.connect(dialog.accept)
        btn_cancel.clicked.connect(dialog.reject)

        btns.addStretch()
        btns.addWidget(btn_ok)
        btns.addWidget(btn_cancel)
        layout.addLayout(btns)

        dialog.setLayout(layout)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        # Captura o item selecionado no QListWidget
        item_selecionado = lista_unidades.currentItem()
        if not item_selecionado:
            return

        # Recupera os dados que guardamos no Qt.UserRole
        nome_curto, root, dtype, nivel = item_selecionado.data(Qt.ItemDataRole.UserRole)

        # obter_info_volume só funciona em volumes lógicos (Ex: "E:\")
        info = obter_info_volume(root) if nivel == "LOGICO" else {}
        if info is None:
            info = {}

        serial_hardware = "Não detectado"
        try:
            if nivel == "LOGICO" and info.get('unidade'):
                letra = info['unidade'].replace(":\\", "").strip()
                ps_script = f"Get-Partition -DriveLetter {letra} | Get-Disk | Select-Object -ExpandProperty SerialNumber"
                resultado = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_script],
                    capture_output=True, text=True, creationflags=0x08000000
                )
                saida = resultado.stdout.strip()
                if saida:
                    serial_hardware = saida
            elif nivel == "FISICO":
                # Se for físico, extrai o índice numérico e usa a função robusta
                num_disco = nome_curto.replace("Disco ", "").strip()
                serial_hardware = obter_serial_hardware(num_disco)
        except Exception:
            pass

        info['serial_hardware'] = serial_hardware

        # --- VERIFICAÇÃO DE RESULTADOS ANTERIORES ---
        # Checa se há dados de extração na memória (se for > 1, já tem resultados)
        if len(self._relatorio_memoria) > 1:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Resultados Anteriores Encontrados")
            fonte = msg_box.font()
            fonte.setPointSize(11)
            msg_box.setFont(fonte)
            msg_box.setText("Já existem resultados de extrações anteriores na tela.")
            msg_box.setInformativeText(
                "Deseja adicionar os resultados da unidade RAW à lista atual ou limpar a tela antes de começar?")
            msg_box.setIcon(QMessageBox.Icon.Question)

            btn_adicionar = msg_box.addButton("Adicionar (Manter histórico)", QMessageBox.ButtonRole.AcceptRole)
            btn_limpar = msg_box.addButton("Limpar tela e substituir", QMessageBox.ButtonRole.DestructiveRole)
            btn_cancelar = msg_box.addButton("Cancelar", QMessageBox.ButtonRole.RejectRole)

            msg_box.exec()

            if msg_box.clickedButton() == btn_cancelar:
                return  # Aborta a aquisição RAW antes de pedir elevação de privilégio
            elif msg_box.clickedButton() == btn_limpar:
                self.texto_saida.clear()
        else:
            self.texto_saida.clear()
        # --------------------------------------------------

        self.texto_saida.append("=== UNIDADE SELECIONADA (RAW) ===")

        if nivel == "LOGICO":
            self.texto_saida.append(f"Letra: {info.get('unidade', 'Desconhecida')}")
            self.texto_saida.append(f"Rótulo: {info.get('rotulo', 'Sem Rótulo')}")
            self.texto_saida.append(f"Serial do Volume (Lógico): {info.get('serial', 'Não detectado')}")
            self.texto_saida.append(f"FS: {info.get('sistema_arquivos', 'RAW')}")
            if 'capacidade' in info:
                self.texto_saida.append(f"Capacidade do Volume Lógico (Partição): {info['capacidade']}")

            # Só exibe o bloco de hardware se NÃO for uma mídia óptica (CD/DVD)
            if get_drive_type(root) != DRIVE_CDROM:
                self.texto_saida.append("\n⚙️  INFORMAÇÕES DE HARDWARE FÍSICO (Device Information):")
                letra_limpa = info.get('unidade', '')
                if letra_limpa:
                    hw_info = obter_info_hardware_por_letra(letra_limpa)
                    self.texto_saida.append(f"Tipo de Conexão (Bus Type): {hw_info['bus_type']}")
                    self.texto_saida.append(f"Dispositivo (Fabricante/Modelo): {hw_info['modelo_fabricante']}")
                    self.texto_saida.append(f"Serial de Fábrica (Hardware): {hw_info['serial']}")

                    # Validação: Sempre exibe a nota técnica se o barramento físico for USB
                    if "USB" in str(hw_info.get('bus_type', '')).upper():
                        self.texto_saida.append(
                            "   ↳ Nota: Caso a mídia analisada (como um cartão SD/MicroSD) esteja conectada através de um adaptador ou leitor USB, o número de série exibido acima pode pertencer ao próprio adaptador e não à unidade física de armazenamento.")
                else:
                    self.texto_saida.append("Hardware físico: Não foi possível mapear a letra da unidade.")
        else:
            # Exibição limpa para Discos Físicos puros
            self.texto_saida.append(f"Caminho Físico: {root}")
            self.texto_saida.append("Tipo: Hardware Direto (Sem Sistema de Arquivos Montado)")
            self.texto_saida.append("\n⚙️  INFORMAÇÕES DE HARDWARE FÍSICO (Device Information):")

            # Agora lê do item_selecionado da lista em vez do combo extinto
            texto_lista = item_selecionado.text()
            # Limpa o texto da interface ("HARDWARE DIRETO: \\.\PhysicalDrive0 [X GB]  -  ") para sobrar só o modelo
            modelo_limpo = texto_lista.split("  -  ")[-1] if "  -  " in texto_lista else texto_lista

            self.texto_saida.append(f"Dispositivo (ID/Modelo): {modelo_limpo}")
            self.texto_saida.append(
                f"Serial de Fábrica (Hardware): {info.get('serial_hardware', 'Não detectado')}")

            # Validação: Para discos físicos brutos, avalia se o modelo reporta conexão USB
            if "USB" in modelo_limpo.upper():
                self.texto_saida.append(
                    "   ↳ Nota: Caso a mídia analisada (como um cartão SD/MicroSD) esteja conectada através de um adaptador ou leitor USB, o número de série exibido acima pode pertencer ao próprio adaptador e não à unidade física de armazenamento.")

        self.texto_saida.append("")

        # --- Diálogo customizado de UAC (Botões Centralizados) ---
        dialog_uac = QDialog(self)
        dialog_uac.setWindowTitle("Elevação de Privilégios")
        dialog_uac.setMinimumWidth(450)

        layout_uac = QVBoxLayout()

        # Texto de aviso
        lbl_aviso = QLabel(
            "A extração RAW requer acesso de baixo nível ao hardware da unidade.<br><br>"
            "<b>ATENÇÃO: será necessário solicitar elevação (UAC).</b><br><br>"
            "O modo administrador será desativado automaticamente ao final do processo."
        )
        lbl_aviso.setWordWrap(True)
        lbl_aviso.setStyleSheet("font-size: 10pt;")
        layout_uac.addWidget(lbl_aviso)

        layout_uac.addSpacing(15)

        # Layout dos botões com stretches nas laterais para centralizar
        layout_botoes = QHBoxLayout()
        btn_autorizar = QPushButton("Autorizar")
        btn_nao_autorizar = QPushButton("Não Autorizar")

        # Deixa os botões com um tamanho padrão mais bonito
        btn_autorizar.setMinimumWidth(120)
        btn_nao_autorizar.setMinimumWidth(120)

        # Adiciona uma cor leve ao botão de autorizar para destacá-lo e implementa os efeitos de interação
        if hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked():
            btn_autorizar.setStyleSheet("""
                        QPushButton {
                            font-weight: bold; 
                            background-color: #3c3f41; 
                            border: 1px solid #555555; 
                            color: #f0f0f0;
                            border-radius: 4px;
                            padding: 6px;
                        }
                        QPushButton:hover { background-color: #4b4d4f; }
                        QPushButton:pressed { background-color: #2b2b2b; }
                    """)
        else:
            btn_autorizar.setStyleSheet("""
                        QPushButton {
                            font-weight: bold; 
                            background-color: #e0e0e0;
                            border: 1px solid #cccccc;
                            color: #111111;
                            border-radius: 4px;
                            padding: 6px;
                        }
                        QPushButton:hover { background-color: #d4d4d4; }
                        QPushButton:pressed { background-color: #c5c5c5; }
                    """)

        # Conecta os botões às ações de aceitar/rejeitar o diálogo
        btn_autorizar.clicked.connect(dialog_uac.accept)
        btn_nao_autorizar.clicked.connect(dialog_uac.reject)

        layout_botoes.addStretch()
        layout_botoes.addWidget(btn_autorizar)
        layout_botoes.addWidget(btn_nao_autorizar)
        layout_botoes.addStretch()

        layout_uac.addLayout(layout_botoes)
        dialog_uac.setLayout(layout_uac)

        # Se o usuário clicar em "Não Autorizar" ou fechar no "X" da janela
        if dialog_uac.exec() != QDialog.DialogCode.Accepted:
            return
        # ---------------------------------------------------------

        # Decide alvo (volume vs physical drive)
        if nivel == "FISICO":
            volume_dev = root  # Já é o PhysicalDrive bruto
            device_path = root
        else:
            volume_dev = drive_root_to_volume_device(root)  # Ex: \\.\I:
            device_path = volume_dev

        if dtype in (DRIVE_REMOVABLE, DRIVE_FIXED, DRIVE_CDROM) or nivel == "FISICO":
            # Cria um diálogo customizado para escolha clara do escopo
            dialog_escopo = QDialog(self)
            dialog_escopo.setWindowTitle("Escopo do Hash RAW (Perícia Forense)")
            dialog_escopo.resize(650, 350)
            layout_escopo = QVBoxLayout()

            lbl_info = QLabel("Escolha a metodologia de extração bit-a-bit:")
            lbl_info.setStyleSheet("font-weight: bold; font-size: 12pt; margin-bottom: 10px;")
            layout_escopo.addWidget(lbl_info)

            # --- Controle de Cores Dinâmicas e Efeitos Táteis para o Escopo RAW ---
            is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
            cor_texto = "#d4d4d4" if is_dark else "#333"

            # Variáveis para os botões (Normal, Hover e Pressed)
            bg_normal = "#3c3f41" if is_dark else "#e0e0e0"
            bg_hover = "#4b4d4f" if is_dark else "#d4d4d4"
            bg_pressed = "#2b2b2b" if is_dark else "#cccccc"
            borda = "1px solid #555555" if is_dark else "1px solid #bfbfbf"
            cor_txt = "#f0f0f0" if is_dark else "#000000"

            # Cores para o estado desativado (disabled) da Abordagem Didática
            bg_dis = "#2b2b2b" if is_dark else "#f0f0f0"
            fg_dis = "#666666" if is_dark else "#a0a0a0"
            bd_dis = "#444444" if is_dark else "#cccccc"

            estilo_botoes_escopo = f"""
                                QPushButton {{
                                    padding: 8px;
                                    font-weight: bold;
                                    font-size: 11pt;
                                    background-color: {bg_normal};
                                    color: {cor_txt};
                                    border: {borda};
                                    border-radius: 4px;
                                }}
                                QPushButton:hover {{ background-color: {bg_hover}; }}
                                QPushButton:pressed {{ background-color: {bg_pressed}; }}
                                QPushButton:disabled {{
                                    background-color: {bg_dis}; 
                                    color: {fg_dis}; 
                                    border: 1px solid {bd_dis}; 
                                    font-weight: normal;
                                }}
                            """

            # --- DEFINIÇÃO DINÂMICA DO TEXTO DA OPÇÃO 1 ---
            texto_opcao1 = "OPÇÃO 1: Disco Físico Inteiro"
            if dtype != DRIVE_CDROM:
                if nivel == "FISICO":
                    texto_opcao1 += f" ({root})"
                else:
                    try:
                        # Identifica o PhysicalDrive real por trás da letra lógica
                        disks = volume_to_physical_drives(volume_dev)
                        if disks:
                            drives_str = ", ".join([f"\\\\.\\PhysicalDrive{d}" for d in disks])
                            texto_opcao1 += f" ({drives_str})"
                    except Exception:
                        pass  # Falha silenciosa, mantém apenas o texto padrão

            # TEXTO OPÇÃO 1
            lbl_titulo_disco = QLabel(f"<b><span style='font-size: 12pt;'>{texto_opcao1}</span></b>")
            lbl_desc_disco = QLabel(
                "<b>O que faz:</b> Acesso irrestrito em nível de hardware. Lê a mídia de ponta a ponta, do primeiro ao último setor físico disponível.<br>"
                "<b>O que captura:</b> Tabelas de inicialização (MBR/GPT), todas as partições (visíveis, ocultas ou com sistemas desconhecidos), espaço não alocado e resíduos entre partições.<br>"
                "<b>Uso Forense:</b> Padrão-ouro para espelhamento pericial completo. Essencial para <i>Data Carving</i> e garantia de que nenhum byte foi deixado para trás."
            )
            lbl_desc_disco.setWordWrap(True)
            lbl_desc_disco.setStyleSheet(f"color: {cor_texto}; font-size: 11pt; margin-bottom: 10px;")

            btn_disco = QPushButton("Selecionar Opção 1 (Hardware Completo)")
            btn_disco.setStyleSheet(estilo_botoes_escopo)

            if dtype == DRIVE_CDROM:
                btn_disco.setEnabled(False)
                btn_disco.setToolTip(
                    "Indisponível: A extração física de hardware (ponta a ponta) não é suportada nativamente para mídias ópticas (CD/DVD).\n"
                    "A operação deverá ser realizada obrigatoriamente através da opção de Volume Lógico."
                )

            # --- DEFINIÇÃO DINÂMICA DO TEXTO DA OPÇÃO 2 ---
            texto_opcao2 = "OPÇÃO 2: Apenas o Volume Lógico"
            if nivel != "FISICO":
                texto_opcao2 += f" ({volume_dev})"

            # TEXTO OPÇÃO 2
            lbl_titulo_volume = QLabel(f"<br><b><span style='font-size: 12pt;'>{texto_opcao2}</span></b>")

            if dtype == DRIVE_CDROM:
                texto_desc_volume = (
                    "<b>O que faz:</b> Acesso lógico delimitado. Lê bit-a-bit exclusivamente a sessão de dados montada pelo sistema operacional.<br>"
                    "<b>O que captura:</b> O sistema de arquivos óptico (ISO9660/UDF/CDFS) e todos os dados e artefatos gravados na mídia.<br>"
                    "<b>Uso Forense:</b> <b>OBRIGATÓRIO PARA MÍDIAS ÓPTICAS (CD/DVD).</b> A arquitetura do Windows exige que o espelhamento forense deste tipo de mídia seja feito através do volume lógico."
                )
            else:
                texto_desc_volume = (
                    "<b>O que faz:</b> Acesso lógico delimitado. Lê bit a bit exclusivamente dentro dos limites da partição selecionada pelo Windows.<br>"
                    "<b>O que captura:</b> O sistema de arquivos (MFT/FAT), arquivos ativos, deletados recuperáveis, <i>File Slack</i> e espaço livre. <b>Ignora</b> o resto do disco.<br>"
                    "<b>Uso Forense:</b> Ideal para triagem rápida. Metodologia recomendada para extrair o conteúdo 'em claro' de partições BitLocker após desbloqueio."
                )

            lbl_desc_volume = QLabel(texto_desc_volume)
            lbl_desc_volume.setWordWrap(True)
            lbl_desc_volume.setStyleSheet(f"color: {cor_texto}; font-size: 11pt; margin-bottom: 10px;")

            btn_volume = QPushButton("Selecionar Opção 2 (Apenas Partição)")
            btn_volume.setStyleSheet(estilo_botoes_escopo)

            if nivel == "FISICO":
                btn_volume.setEnabled(False)
                btn_volume.setToolTip(
                    "Indisponível: O hardware selecionado é o disco físico bruto.\nNão há partição lógica isolada mapeada nesta seleção.")

            # Lógica de seleção
            escolha = {"tipo": "volume"}

            def set_disco():
                escolha["tipo"] = "disco"
                dialog_escopo.accept()

            def set_volume():
                escolha["tipo"] = "volume"
                dialog_escopo.accept()

            btn_disco.clicked.connect(set_disco)
            btn_volume.clicked.connect(set_volume)

            # Montagem do Layout
            layout_escopo.addWidget(lbl_titulo_disco)
            layout_escopo.addWidget(lbl_desc_disco)
            layout_escopo.addWidget(btn_disco)

            layout_escopo.addWidget(lbl_titulo_volume)
            layout_escopo.addWidget(lbl_desc_volume)
            layout_escopo.addWidget(btn_volume)

            layout_escopo.addStretch()

            btn_cancelar_escopo = QPushButton("Cancelar Operação")
            btn_cancelar_escopo.clicked.connect(dialog_escopo.reject)
            layout_escopo.addWidget(btn_cancelar_escopo)

            dialog_escopo.setLayout(layout_escopo)

            if dialog_escopo.exec() != QDialog.DialogCode.Accepted:
                return

            if escolha["tipo"] == "disco":
                if nivel == "FISICO":
                    # Evita o erro de tentar converter o que já é PhysicalDrive em PhysicalDrive
                    device_path = root
                    self._raw_metodo_escolhido = "Disco Físico Inteiro (Acesso direto ao Hardware)"
                else:
                    try:
                        disks = volume_to_physical_drives(volume_dev)
                        if not disks:
                            raise RuntimeError("Não foi possível mapear volume -> PhysicalDrive")
                        if len(disks) > 1:
                            QMessageBox.warning(self, "Aviso",
                                                f"Volume mapeado para múltiplos discos físicos: {disks}. Usando o primeiro.")
                        # noinspection PyUnusedLocal
                        device_path = r"\\.\PhysicalDrive{}".format(disks[0])
                        self._raw_metodo_escolhido = "Disco Físico Inteiro (Acesso direto ao Hardware)"

                    except Exception as e:
                        QMessageBox.critical(self, "Erro Mapeamento",
                                             f"Falha ao obter PhysicalDrive (Erro: {e}).\n\nUsando o volume ({volume_dev}) como alternativa.")
                        device_path = volume_dev
                        # SALVA A ESCOLHA (FALLBACK)
                        self._raw_metodo_escolhido = "Volume Lógico (Fallback por falha no mapeamento físico)"
            else:
                device_path = volume_dev
                # SALVA A ESCOLHA (OPÇÃO 2)
                self._raw_metodo_escolhido = "Apenas Volume Lógico (Delimitado pelo S.O.)"

        # --- DIÁLOGO CUSTOMIZADO: AQUISIÇÃO DE IMAGEM FORENSE ---
        caminho_imagem = ""
        dialog_imagem = QDialog(self)
        dialog_imagem.setWindowTitle("Aquisição de Imagem Forense")
        dialog_imagem.setMinimumWidth(800)  # Aumentado levemente para acomodar a explicação

        layout_img = QVBoxLayout()

        # Texto de aviso principal atualizado para abranger a compactação do E01
        lbl_aviso_img = QLabel(
            "Deseja também salvar uma cópia bit-a-bit (imagem .dd ou .E01) desta unidade durante a extração do Hash?\n\n"
            "⚠️ ATENÇÃO AOS REQUISITOS DE ESPAÇO:\n"
            " • Formato RAW (.dd): Requer espaço livre no destino RIGOROSAMENTE IGUAL ao tamanho total da unidade de origem.\n"
            " • Formato Expert Witness (.E01): O arquivo gerado é COMPACTADO, o que pode requerer significativamente menos espaço em disco do que o tamanho físico total da mídia periciada.\n\n"
            "🚨 NUNCA salve a imagem dentro da própria unidade que está sendo analisada."
        )
        lbl_aviso_img.setWordWrap(True)
        lbl_aviso_img.setStyleSheet("font-size: 13pt; font-weight: bold;")
        layout_img.addWidget(lbl_aviso_img)

        layout_img.addSpacing(15)

        # Layout dos botões centralizados
        layout_botoes_img = QHBoxLayout()
        btn_sim = QPushButton("SIM.\nGere o HASH e a cópia bit-a-bit.")
        btn_nao = QPushButton("NÃO.\nGere apenas o HASH.")

        btn_sim.setMinimumWidth(250)
        btn_nao.setMinimumWidth(200)

        # --- AUMENTANDO O TAMANHO DO TEXTO DOS BOTÕES ---
        btn_sim.setStyleSheet("font-size: 11pt; font-weight: bold; padding: 6px;")
        btn_nao.setStyleSheet("font-size: 11pt; font-weight: bold; padding: 6px;")

        # Conexões explícitas com inteiros
        btn_sim.clicked.connect(lambda: dialog_imagem.done(1))  # 1 = SIM
        btn_nao.clicked.connect(lambda: dialog_imagem.done(2))  # 2 = NÃO

        layout_botoes_img.addStretch()
        layout_botoes_img.addWidget(btn_sim)
        layout_botoes_img.addWidget(btn_nao)
        layout_botoes_img.addStretch()

        layout_img.addLayout(layout_botoes_img)

        # --- LINHA DE SEPARAÇÃO ---
        layout_img.addSpacing(10)  # Espaço antes da linha

        linha_divisoria = QFrame()
        linha_divisoria.setFrameShape(QFrame.Shape.HLine)
        linha_divisoria.setFrameShadow(QFrame.Shadow.Sunken)
        layout_img.addWidget(linha_divisoria)

        layout_img.addSpacing(10)  # Espaço depois da linha

        # --- Cores dinâmicas para a Nota Técnica ---
        is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
        bg_nota = "#2b2b2b" if is_dark else "#f9f9f9"
        borda_nota = "#555555" if is_dark else "#ddd"
        cor_nota = "#d4d4d4" if is_dark else "#333"
        cor_link = "#66b2ff" if is_dark else "#0056b3"

        # --- BOTÃO EXPANSÍVEL (TOGGLE) ---
        btn_toggle_nota = QPushButton("▶ Mostrar Nota Técnica sobre Montagem de Imagens RAW")
        btn_toggle_nota.setCheckable(True)
        btn_toggle_nota.setCursor(Qt.CursorShape.PointingHandCursor)  # Muda o cursor para "mãozinha"
        btn_toggle_nota.setStyleSheet(f"""
                    QPushButton {{
                        text-align: left;
                        border: none;
                        background: transparent;
                        font-weight: bold;
                        font-size: 11pt;
                        color: {cor_link};
                        padding: 5px 0px;
                    }}
                    QPushButton:hover {{
                        text-decoration: underline;
                    }}
                """)

        # --- NOTA TÉCNICA SOBRE ABERTURA DE ARQUIVOS .DD ---
        # Removi o título em negrito de dentro da caixa HTML, pois o botão já faz esse papel
        lbl_nota_tecnica = QLabel(
            f"<div style='background-color: {bg_nota}; border: 1px solid {borda_nota}; padding: 12px; border-radius: 5px; color: {cor_nota};'>"
            "O uso de softwares como <b>Daemon Tools não é recomendado</b> para perícia. Ele foi projetado para "
            "emular mídias ópticas (ISO, MDS) e não interpreta corretamente tabelas de partição (MBR/GPT) ou sistemas "
            "de arquivos (NTFS, exFAT) embutidos em imagens de discos rígidos e pendrives.<br><br>"
            "Para preservar a integridade da evidência, utilize ferramentas que forcem o modo <b>Somente-Leitura (Read-Only)</b> "
            "e emulem o disco físico real. Sugestões:<br><br>"
            "• <b>Arsenal Image Mounter (AIM):</b> O padrão-ouro atual. A versão gratuita suporta emulação SCSI, ideal para volumes complexos e BitLocker.<br>"
            "• <b>FTK Imager:</b> Ferramenta totalmente gratuita e consolidada na comunidade forense que possui a opção 'Mount Image' nativa.<br>"
            "• <b>OSFMount:</b> Leve e versátil, permite montar a imagem RAW rapidamente, inclusive alocando-a em RAM "
            "se necessário para maior performance. É totalmente gratuita e consolidada na comunidade forense.<br>"
            "</div>"
        )
        lbl_nota_tecnica.setWordWrap(True)
        lbl_nota_tecnica.setStyleSheet("font-size: 11pt;")
        lbl_nota_tecnica.setVisible(False)  # <-- O SEGREDO: Começa invisível

        # Função para alternar a visibilidade da caixa e o texto da setinha do botão
        def alternar_nota(checked):
            lbl_nota_tecnica.setVisible(checked)
            if checked:
                btn_toggle_nota.setText("▼ Ocultar Nota Técnica sobre Montagem de Imagens RAW")
            else:
                btn_toggle_nota.setText("▶ Mostrar Nota Técnica sobre Montagem de Imagens RAW")

            # Força a janela a recalcular seu tamanho para não deixar espaços em branco
            dialog_imagem.adjustSize()

        # Conecta o clique do botão à função acima
        btn_toggle_nota.toggled.connect(alternar_nota)

        # Adiciona os novos widgets ao layout da janela
        layout_img.addWidget(btn_toggle_nota)
        layout_img.addWidget(lbl_nota_tecnica)

        dialog_imagem.setLayout(layout_img)

        # --- AVALIAÇÃO DA RESPOSTA DO USUÁRIO ---
        resultado_imagem = dialog_imagem.exec()

        # Se o usuário fechou a janela no 'X' (ausência de escolha)
        if resultado_imagem == 0:
            # 0 é o retorno padrão do PySide6 quando o usuário fecha a janela no "X"
            self.texto_saida.append("\n[!] Operação cancelada pelo usuário (Janela fechada).")
            return  # Aborta tudo e mantém no modo não-admin

        if resultado_imagem == 1:
            # --- 1. JANELA DE SELEÇÃO: DD vs E01 ---
            dialog_formato = QDialog(self)
            dialog_formato.setWindowTitle("Selecionar Formato da Imagem")
            dialog_formato.setMinimumWidth(550)  # Aumentada um pouco para acomodar os novos textos
            layout_formato = QVBoxLayout(dialog_formato)

            lbl_f = QLabel("Escolha o formato de saída para a cópia bit-a-bit:")
            lbl_f.setStyleSheet("font-size: 12pt; font-weight: bold; margin-bottom: 10px;")
            layout_formato.addWidget(lbl_f)

            # --- INSTÂNCIA DOS BOTÕES (E01 ganha precedência na tela) ---
            btn_e01 = QPushButton("Formato Expert Witness (.E01) - RECOMENDADO")
            btn_dd = QPushButton("Formato RAW / Bruto (.dd)")

            # --- TOOLTIPS FORENSES (Explicando as vantagens) ---
            btn_e01.setToolTip(
                "<table width='350'><tr><td style='padding: 5px; font-size: 11pt; line-height: 1.3;'>"
                "<p><b>Padrão-Ouro da Perícia Digital</b></p>"
                "<ul>"
                "<li><b>Espaço:</b> Utiliza compactação de dados avançada, economizando gigabytes no seu HD de destino.</li>"
                "<li><b>Integridade:</b> Embute hashes (MD5) bloco a bloco dentro do contêiner para blindar a prova contra corrupção parcial.</li>"
                "<li><b>Metadados:</b> Salva o nome do perito, laudo e descrição selados junto com a imagem.</li>"
                "</ul></td></tr></table>"
            )

            btn_dd.setToolTip(
                "<table width='350'><tr><td style='padding: 5px; font-size: 11pt; line-height: 1.3;'>"
                "<p><b>Cópia Bruta (1:1)</b></p>"
                "<ul>"
                "<li><b>Espaço:</b> Ocupará EXATAMENTE o mesmo tamanho físico da mídia original (Ex: Pendrive de 64GB = Arquivo de 64GB), mesmo se o disco estiver completamente vazio.</li>"
                "<li><b>Integridade:</b> Não possui compressão, nem cabeçalhos, nem hashes embutidos.</li>"
                "<li><b>Uso:</b> Recomendado apenas se o software de análise posterior não suportar contêineres modernos.</li>"
                "</ul></td></tr></table>"
            )

            # --- CORES DINÂMICAS PARA DAR ÊNFASE AO E01 ---
            is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()

            # Estilo de Destaque para o E01 (Azul Suave/Profundo)
            bg_e01 = "#004080" if is_dark else "#e6f2ff"
            fg_e01 = "#ffffff" if is_dark else "#005a9e"
            bd_e01 = "#003366" if is_dark else "#b3d4ff"
            hv_e01 = "#0059b3" if is_dark else "#cce5ff"
            pr_e01 = "#002b5e" if is_dark else "#99ccff"

            btn_e01.setStyleSheet(f"""
                            QPushButton {{
                                font-size: 11pt; font-weight: bold; padding: 12px;
                                background-color: {bg_e01}; color: {fg_e01}; 
                                border: 2px solid {bd_e01}; border-radius: 5px;
                            }}
                            QPushButton:hover {{ background-color: {hv_e01}; }}
                            QPushButton:pressed {{ background-color: {pr_e01}; }}
                        """)

            # Estilo Neutro para o DD (Cinza Padrão)
            bg_dd = "#3c3f41" if is_dark else "#f4f4f4"
            fg_dd = "#d4d4d4" if is_dark else "#555555"
            bd_dd = "#555555" if is_dark else "#cccccc"
            hv_dd = "#4b4d4f" if is_dark else "#e0e0e0"
            pr_dd = "#2b2b2b" if is_dark else "#d0d0d0"

            btn_dd.setStyleSheet(f"""
                            QPushButton {{
                                font-size: 11pt; font-weight: normal; padding: 8px;
                                background-color: {bg_dd}; color: {fg_dd}; 
                                border: 1px solid {bd_dd}; border-radius: 4px;
                            }}
                            QPushButton:hover {{ background-color: {hv_dd}; }}
                            QPushButton:pressed {{ background-color: {pr_dd}; }}
                        """)

            # --- INVERSÃO NA TELA: Adiciona o E01 Primeiro ---
            layout_formato.addWidget(btn_e01)
            layout_formato.addWidget(btn_dd)

            formato_escolhido = {"ext": ".dd", "meta": {}}

            btn_dd.clicked.connect(lambda: dialog_formato.done(1))
            btn_e01.clicked.connect(lambda: dialog_formato.done(2))

            res_formato = dialog_formato.exec()
            if res_formato == 0:
                self.texto_saida.append("\n[!] Operação cancelada pelo usuário (Seleção de formato).")
                return

            if res_formato == 2:
                # --- 2. TRAVA DE SEGURANÇA: VERIFICA SE O EWFACQUIRE EXISTE ---
                if obter_caminho_ewfacquire() is None:
                    mensagem_aviso = (
                        "O utilitário 'ewfacquire.exe' não foi encontrado!\n\n"
                        "Para gerar imagens .E01, você precisa baixar o 'libewf-msvscpp' "
                        "(binários para Windows) e colocar o arquivo 'ewfacquire.exe' "
                        "dentro de uma pasta chamada 'ewf' ao lado deste programa."
                    )
                    QMessageBox.critical(self, "ewfacquire Ausente", mensagem_aviso)
                    self.texto_saida.append("\n[!] Operação cancelada: ewfacquire.exe não encontrado.")
                    return

                # --- 3. COLETAR METADADOS (Pode vir vazio, o Passo 1 já lida com isso) ---
                dialogo_meta = DialogoMetadadosKML(self, texto_botao="Continuar e Gerar Imagem .E01", modo_e01=True)
                dialogo_meta.setWindowTitle("Cabeçalho Forense do Arquivo E01")
                if dialogo_meta.exec() != QDialog.DialogCode.Accepted:
                    self.texto_saida.append("\n[!] Operação cancelada pelo usuário na tela de metadados.")
                    return
                formato_escolhido["ext"] = ".e01"
                formato_escolhido["meta"] = dialogo_meta.obter_dados()

            # --- 4. SELEÇÃO DE DESTINO DA IMAGEM ---
            nome_da_imagem = f"imagem_forense_{info.get('serial') or 'raw'}"

            while True:
                # noinspection PyTypeChecker
                opcoes_dir = QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog
                diretorio_escolhido = QFileDialog.getExistingDirectory(self, "Selecione o local para salvar",
                                                                       options=opcoes_dir)

                if diretorio_escolhido:
                    # Normaliza a barra invertida (\) do Windows logo na saída do Qt
                    diretorio_escolhido = os.path.normpath(diretorio_escolhido)

                    pasta_evidencia = os.path.join(diretorio_escolhido, f"{nome_da_imagem}_evidencia")
                    os.makedirs(pasta_evidencia, exist_ok=True)

                    caminho_imagem = os.path.join(pasta_evidencia, f"{nome_da_imagem}{formato_escolhido['ext']}")
                    self._caminho_audit_log = os.path.join(pasta_evidencia, f"{nome_da_imagem}_auditoria.txt")

                    self._raw_caminho_relatorio_auto = os.path.join(pasta_evidencia,
                                                                    f"{nome_da_imagem}_relatorio_completo.txt")

                    self._raw_metodo_escolhido += f" + Geração de Imagem ({formato_escolhido['ext'].upper()})"
                    break
                else:
                    self.texto_saida.append("\n[!] Operação cancelada (Destino não selecionado).")
                    return

            # Chama a função de processamento (Note o novo parâmetro metadados adicionado!)
            self._iniciar_raw_hash_elevado(device_path, caminho_imagem, formato_escolhido["meta"])


        elif resultado_imagem == 2:
            # O usuário quer APENAS extrair o hash RAW, sem gerar arquivo .dd ou .E01

            # --- Pergunta sobre o Auto-Salvamento ---
            msg_auto = QMessageBox(self)
            msg_auto.setWindowTitle("Auto-salvar Relatório (Recomendado)")

            # Aplica o padrão de fonte maior
            fonte = msg_auto.font()
            fonte.setPointSize(11)
            msg_auto.setFont(fonte)

            # Coloca o texto principal em negrito para manter a consistência
            msg_auto.setText("<b>A extração RAW pode demorar horas.</b>")
            msg_auto.setInformativeText(
                "Deseja selecionar uma pasta para o programa salvar o relatório final (.txt) automaticamente ao término da operação (evitando perda de dados em caso de queda de energia)?"
            )
            msg_auto.setIcon(QMessageBox.Icon.Question)

            btn_sim = msg_auto.addButton("Sim, escolher pasta", QMessageBox.ButtonRole.AcceptRole)
            btn_nao = msg_auto.addButton("Não, exibir apenas na tela", QMessageBox.ButtonRole.RejectRole)

            # Aplica o padrão visual dos botões (Modo Escuro / Claro) do resto do app
            is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
            if is_dark:
                btn_sim.setStyleSheet("""
                                QPushButton { padding: 6px 12px; font-weight: bold; background-color: #3c3f41; border: 1px solid #555555; border-radius: 4px; color: #ffffff; }
                                QPushButton:hover { background-color: #505355; border: 1px solid #777777; }
                                QPushButton:pressed { background-color: #2b2d2e; border: 1px solid #999999; }
                            """)
                btn_nao.setStyleSheet("""
                                QPushButton { padding: 6px 12px; background-color: #2b2b2b; border: 1px solid #444444; border-radius: 4px; color: #ffffff; }
                                QPushButton:hover { background-color: #3b3b3b; border: 1px solid #666666; }
                                QPushButton:pressed { background-color: #1a1a1a; border: 1px solid #888888; }
                            """)
            else:
                btn_sim.setStyleSheet("""
                                QPushButton { padding: 6px 12px; font-weight: bold; background-color: #e0e0e0; border: 1px solid #cccccc; border-radius: 4px; color: #000000; }
                                QPushButton:hover { background-color: #d0d0d0; border: 1px solid #aaaaaa; }
                                QPushButton:pressed { background-color: #c0c0c0; border: 1px solid #888888; }
                            """)
                btn_nao.setStyleSheet("""
                                QPushButton { padding: 6px 12px; background-color: #ffffff; border: 1px solid #cccccc; border-radius: 4px; color: #000000; }
                                QPushButton:hover { background-color: #eeeeee; border: 1px solid #bbbbbb; }
                                QPushButton:pressed { background-color: #dddddd; border: 1px solid #999999; }
                            """)

            msg_auto.exec()

            if msg_auto.clickedButton() == btn_sim:
                opcoes_dir = QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog
                dir_escolhido = QFileDialog.getExistingDirectory(self, "Selecione a pasta para auto-salvar o relatório",
                                                                 options=opcoes_dir)
                if dir_escolhido:
                    agora = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    nome_arq = f"Relatorio_Extracao_RAW_{agora}.txt"
                    self._raw_caminho_relatorio_auto = os.path.join(os.path.normpath(dir_escolhido), nome_arq)
                else:
                    self.texto_saida.append("\n[!] Operação cancelada (Destino do relatório não selecionado).")
                    return
            else:
                self._raw_caminho_relatorio_auto = None

            self._iniciar_raw_hash_elevado(device_path)


    def _iniciar_raw_hash_elevado(self, device_path: str, caminho_imagem: str = "", metadados_e01: dict = None):
        lf, _ = try_acquire_raw_device_lock(device_path)
        if lf is None:
            QMessageBox.warning(self, "RAW em andamento",
                                f"Já existe uma aquisição RAW em andamento para: {device_path}")
            return
        release_raw_device_lock(lf)

        # ---> REDE DE SEGURANÇA PARA VALIDAR CADEIA DE CUSTÓDIA DE UNIDADES RAW <---
        # Lê o texto que estiver na caixa de custódia e faz a verificação
        texto_custodia = self.texto_referencia.toPlainText().strip()
        texto_custodia = self._verificar_pre_extracao_custodia(texto_custodia)
        if texto_custodia is None:
            return
        # ---------------------------------------------------------------------------

        algos = [algo for algo, chk in self.chk_hashes.items() if chk.isChecked()]
        if not algos:
            QMessageBox.warning(self, "Algoritmos", "Selecione ao menos um algoritmo de hash.")
            return

        # =========================================================
        # DESVIO: SE FOR E01, PASSA O COMANDO PARA O EWFACQUIRE
        # =========================================================
        if caminho_imagem.lower().endswith('.e01'):

            # --- AVISO SOBRE VALIDAÇÃO DE CADEIA DE CUSTÓDIA NO E01 ---
            if texto_custodia:
                msg_box = QMessageBox(self)
                msg_box.setWindowTitle("Aviso Forense - E01 e Cadeia de Custódia")

                fonte = msg_box.font()
                fonte.setPointSize(11)
                msg_box.setFont(fonte)

                msg_box.setText(
                    "<b>A extração no formato .E01 não permite validação de cadeia de custódia simultânea.</b>")
                msg_box.setInformativeText(
                    "O formato E01 possui uma validação automática pós-extração, mas ela serve exclusivamente "
                    "para validar o próprio processo de aquisição (garantindo que o espelhamento ocorreu sem corromper os dados).\n\n"
                    "Essa validação não cruzará dados com os hashes da cadeia de custódia que você inseriu na tela principal.\n\n"
                    "Deseja prosseguir com a geração da imagem .E01 assim mesmo?"
                )
                msg_box.setIcon(QMessageBox.Icon.Information)

                btn_prosseguir = msg_box.addButton("Prosseguir", QMessageBox.ButtonRole.AcceptRole)
                btn_cancelar = msg_box.addButton("Cancelar", QMessageBox.ButtonRole.RejectRole)

                is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
                if is_dark:
                    btn_prosseguir.setStyleSheet("""
                            QPushButton { padding: 6px 12px; font-weight: bold; background-color: #3c3f41; border: 1px solid #555555; border-radius: 4px; color: #ffffff; }
                            QPushButton:hover { background-color: #505355; border: 1px solid #777777; }
                            QPushButton:pressed { background-color: #2b2d2e; border: 1px solid #999999; }
                        """)
                    btn_cancelar.setStyleSheet("""
                            QPushButton { padding: 6px 12px; background-color: #2b2b2b; border: 1px solid #444444; border-radius: 4px; color: #ffffff; }
                            QPushButton:hover { background-color: #3b3b3b; border: 1px solid #666666; }
                            QPushButton:pressed { background-color: #1a1a1a; border: 1px solid #888888; }
                        """)
                else:
                    btn_prosseguir.setStyleSheet("""
                            QPushButton { padding: 6px 12px; font-weight: bold; background-color: #e0e0e0; border: 1px solid #cccccc; border-radius: 4px; color: #000000; }
                            QPushButton:hover { background-color: #d0d0d0; border: 1px solid #aaaaaa; }
                            QPushButton:pressed { background-color: #c0c0c0; border: 1px solid #888888; }
                        """)
                    btn_cancelar.setStyleSheet("""
                            QPushButton { padding: 6px 12px; background-color: #ffffff; border: 1px solid #cccccc; border-radius: 4px; color: #000000; }
                            QPushButton:hover { background-color: #eeeeee; border: 1px solid #bbbbbb; }
                            QPushButton:pressed { background-color: #dddddd; border: 1px solid #999999; }
                        """)

                msg_box.exec()

                if msg_box.clickedButton() == btn_cancelar:
                    return

                # Registra o aviso rapidamente no painel traseiro
                self.texto_saida.append(
                    "⚠️ AVISO: Validação de Custódia ignorada (Formato E01 não suporta validação simultânea).")
            # -----------------------------------------------

            self.travar_interface()

            # --- ATIVA A ANIMAÇÃO DE "VAI E VEM" (MODO INDETERMINADO) ---
            self.barra_arquivo.setMinimum(0)
            self.barra_arquivo.setMaximum(0)
            self.barra_total.setMinimum(0)
            self.barra_total.setMaximum(0)
            # ------------------------------------------------------------

            self.lbl_progresso_arquivo.setText("Progresso do Arquivo Atual: Gerando imagem .E01 (Aguarde...)")
            self.lbl_progresso_total.setText("Executando aquisição forense via ewfacquire...")
            self._ativar_modo_admin_visual()
            self.cancelar_operacao = False

            try:
                # O Python fica bloqueado aguardando o processo C++ terminar
                executar_aquisicao_e01_ewf(device_path, caminho_imagem, metadados_e01)

                self.texto_saida.append("\n=== AQUISIÇÃO E01 FINALIZADA COM SUCESSO ===")
                self.texto_saida.append(f"Metodologia: {self._raw_metodo_escolhido}")
                self.texto_saida.append(f"Dispositivo: {device_path}")
                self.texto_saida.append(f"Imagem gerada: {caminho_imagem}")

                # ========================================================
                # NOVA SEÇÃO: CAPTURA DO HASH NATIVO DO EWFACQUIRE
                # ========================================================
                caminho_log_ewf = os.path.splitext(caminho_imagem)[0] + ".ewf.log"
                if os.path.exists(caminho_log_ewf):
                    # Guarda o SHA-256 da coleta para usar na verificação
                    sha256_coleta = None

                    try:
                        with open(caminho_log_ewf, "r", encoding="utf-8", errors="ignore") as f_log_ewf:
                            conteudo_ewf = f_log_ewf.read()

                            matches = re.finditer(r'(MD5|SHA1|SHA256)\s+hash calculated over data:\s+([a-fA-F0-9]+)',
                                                  conteudo_ewf, re.IGNORECASE)

                            teve_hash = False
                            for match in matches:
                                if not teve_hash:
                                    self.texto_saida.append("📄 Hashes Nativos (gerados pelo ewfacquire):")
                                    teve_hash = True

                                algo_nativo = match.group(1).upper()
                                hash_nativo = match.group(2).upper()
                                self.texto_saida.append(f"   {algo_nativo} do Payload: {hash_nativo}")

                                # SE FOR SHA-256, GUARDA NA MEMÓRIA!
                                if algo_nativo == "SHA256":
                                    sha256_coleta = hash_nativo

                            # if teve_hash:
                            #     self.texto_saida.append(
                            #         "   (Nota: Estes valores representam os dados brutos da mídia e podem ser conferidos ao carregar o arquivo .E01 em softwares forenses, como o FTK Imager)\n")
                    except Exception as e:
                        self.texto_saida.append(f"⚠️ Aviso: Não foi possível ler o log do ewfacquire: {e}")

                self.texto_saida.append("\n")
                # ========================================================

                # ========================================================
                # ETAPA: HASHING PÓS-AQUISIÇÃO DO E01 E GERAÇÃO DE LOG
                # ========================================================
                # Removemos o print fixo na tela e usamos apenas a barra de status como "pulmão"
                self.lbl_progresso_total.setText("Verificando integridade pós-aquisição. Aguarde...")
                QApplication.processEvents()

                import glob
                import datetime
                base_name = os.path.splitext(caminho_imagem)[0]

                # Coleta apenas os pedaços da imagem (.e01, .e02...)
                arquivos_imagem = sorted([f for f in glob.glob(f"{base_name}.*") if
                                          f.lower().endswith(('.e01')) or re.match(r'\.e\d{2}$',
                                                                                            os.path.splitext(f)[
                                                                                                1].lower())])
                arquivo_log = f"{base_name}.ewf.log"

                linhas_log_auditoria = []

                if not arquivos_imagem:
                    self.texto_saida.append(
                        "⚠️ Aviso: O arquivo de imagem não foi localizado no disco após a extração.")
                    linhas_log_auditoria.append("FALHA: Arquivos de imagem não localizados após a extração ewfacquire.")
                else:
                    arq_principal = arquivos_imagem[0]
                    nome_arq_principal = os.path.basename(arq_principal)

                    # 1. VALIDAÇÃO CRIPTOGRÁFICA (EWFVERIFY)
                    if sha256_coleta and arq_principal.lower().endswith(('.e01')):

                        # Verifica se o usuário desmarcou a validação
                        if metadados_e01 and not metadados_e01.get("fazer_validacao", True):
                            msg_pulo = f"\n📄 Validação Criptográfica Automática ({nome_arq_principal}): IGNORADA (Desmarcada pelo usuário)."
                            self.texto_saida.append(msg_pulo)
                            linhas_log_auditoria.append(msg_pulo.strip())

                        else:
                            msg_hash_logico = f"\n📄 Validação Criptográfica Automática Pós-extração ({nome_arq_principal}):"
                            self.texto_saida.append(msg_hash_logico)
                            linhas_log_auditoria.append(msg_hash_logico.strip())

                            # noinspection PyUnresolvedReferences
                            self.texto_saida._original_append(
                                "   🔄 Terminal de verificação aberto. Acompanhe o progresso na nova janela...")
                            QApplication.processEvents()

                            sucesso, msg_verificacao = verificar_integridade_automatica(arq_principal, sha256_coleta)

                            # Apaga o "Aguarde..." da tela
                            cursor = self.texto_saida.textCursor()
                            cursor.movePosition(QTextCursor.MoveOperation.End)
                            cursor.select(QTextCursor.SelectionType.BlockUnderCursor)
                            cursor.removeSelectedText()

                            self.texto_saida.append(msg_verificacao)
                            linhas_log_auditoria.append(msg_verificacao)

                    # 2. HASH DOS ARQUIVOS FÍSICOS DA IMAGEM (.E01, .E02...)
                    for arq_img in arquivos_imagem:
                        nome_arq = os.path.basename(arq_img)
                        msg_hash_fisico = f"\n📄 Hashes do Arquivo Físico ({nome_arq}):"
                        self.texto_saida.append(msg_hash_fisico)
                        linhas_log_auditoria.append(msg_hash_fisico.strip())

                        res_hash = self.obter_metadados_e_hashes(arq_img, algos, extrair_metadados=False)
                        if res_hash.get('sucesso'):
                            for algo in algos:
                                if algo in res_hash['hashes']:
                                    linha_h = f"   {algo}: {res_hash['hashes'][algo]}"
                                    self.texto_saida.append(linha_h)
                                    linhas_log_auditoria.append(linha_h)
                        else:
                            erro_msg = f"   ❌ Erro ao calcular hash físico: {res_hash.get('erro')}"
                            self.texto_saida.append(erro_msg)
                            linhas_log_auditoria.append(erro_msg)

                    # 3. HASH DO ARQUIVO DE LOG DE AUDITORIA (.ewf.log) NO FINAL
                    if os.path.exists(arquivo_log):
                        nome_log = os.path.basename(arquivo_log)
                        msg_hash_log = f"\n📄 Hashes do Arquivo Físico ({nome_log}):"
                        self.texto_saida.append(msg_hash_log)
                        linhas_log_auditoria.append(msg_hash_log.strip())

                        res_hash_log = self.obter_metadados_e_hashes(arquivo_log, algos, extrair_metadados=False)
                        if res_hash_log.get('sucesso'):
                            for algo in algos:
                                if algo in res_hash_log['hashes']:
                                    linha_h = f"   {algo}: {res_hash_log['hashes'][algo]}"
                                    self.texto_saida.append(linha_h)
                                    linhas_log_auditoria.append(linha_h)
                        else:
                            erro_msg = f"   ❌ Erro ao calcular hash físico do log: {res_hash_log.get('erro')}"
                            self.texto_saida.append(erro_msg)
                            linhas_log_auditoria.append(erro_msg)

                self.texto_saida.append("")

                # --- GRAVAÇÃO DO ARQUIVO DE AUDITORIA FÍSICO (.TXT) ---
                if hasattr(self, '_caminho_audit_log') and self._caminho_audit_log:
                    try:
                        with open(self._caminho_audit_log, "w", encoding="utf-8") as f_log:
                            f_log.write("=" * 55 + "\n")
                            f_log.write(f"LOG DE AUDITORIA FORENSE - {NOME_APP} - versão {VERSAO_APP}\n")
                            f_log.write("=" * 55 + "\n\n")

                            f_log.write(
                                f"Data/Hora Conclusão: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
                            if hasattr(self, '_raw_metodo_escolhido'):
                                f_log.write(f"Metodologia: {self._raw_metodo_escolhido}\n")
                            f_log.write(f"Alvo da Extração: {device_path}\n")
                            f_log.write(f"Imagem gerada: {caminho_imagem}\n\n")

                            f_log.write("HASHES DA IMAGEM E01 (PÓS-AQUISIÇÃO):\n")
                            for linha in linhas_log_auditoria:
                                f_log.write(f"{linha}\n")

                            f_log.write("\n" + "=" * 55 + "\n")
                    except Exception as e:
                        self.texto_saida.append(f"\nERRO: Falha ao gerar arquivo de auditoria físico: {e}")
                # ========================================================

            except Exception as e:
                self.texto_saida.append(f"\n ❌ ERRO NA AQUISIÇÃO E01:\n{str(e)}\n")
                self._desativar_modo_admin_visual()
                self.destravar_interface()

                # Restaura as barras parando a animação e zera os valores
                self.barra_arquivo.setMinimum(0)
                self.barra_arquivo.setMaximum(100)
                self.barra_total.setMinimum(0)
                self.barra_total.setMaximum(100)
                self.barra_arquivo.setValue(0)
                self.barra_total.setValue(0)

                self.lbl_progresso_arquivo.setText("Progresso do Arquivo Atual: Cancelado / Erro")
                self.lbl_progresso_total.setText("Progresso RAW - Cancelado / Erro")

                self._salvar_relatorio_automatico()
                return

            # SE DEU TUDO CERTO, RODA A FINALIZAÇÃO NORMAL DE SUCESSO AQUI:
            self._desativar_modo_admin_visual()
            self.destravar_interface()

            # --- RESTAURA AS BARRAS PARA O MODO PORCENTAGEM PADRÃO ---
            self.barra_arquivo.setMinimum(0)
            self.barra_arquivo.setMaximum(100)
            self.barra_total.setMinimum(0)
            self.barra_total.setMaximum(100)
            # ---------------------------------------------------------

            self.barra_arquivo.setValue(100)
            self.barra_total.setValue(100)
            self.lbl_progresso_arquivo.setText("Progresso do Arquivo Atual: Concluído!")
            self.lbl_progresso_total.setText("Progresso RAW - Concluído!")

            self._salvar_relatorio_automatico()
            return

        # =========================================================
        # FLUXO ORIGINAL: SE FOR .DD / RAW
        # =========================================================
        out_json, progress_json, cancel_flag = self._temp_paths_raw()
        self._raw_out_json = out_json
        self._raw_progress_json = progress_json
        self._raw_cancel_flag = cancel_flag
        self._raw_device = device_path
        self._raw_caminho_imagem = caminho_imagem

        self.travar_interface()
        self.barra_total.setMaximum(100)
        self.barra_total.setValue(0)
        self.lbl_progresso_total.setText("Progresso RAW - Iniciando...")
        self._ativar_modo_admin_visual()

        self.cancelar_operacao = False
        self.btn_cancelar.setText("CANCELAR PROCESSAMENTO")
        self.btn_cancelar.setEnabled(True)

        rc = run_raw_helper_elevated(
            device_path=device_path,
            algos=algos,
            chunk_size=1024 * 1024,
            out_json_path=out_json,
            progress_json_path=progress_json,
            cancel_flag_path=cancel_flag,
            image_out_path=caminho_imagem
        )

        if rc <= 32:
            self._desativar_modo_admin_visual()
            self.destravar_interface()
            if rc == 5:
                QMessageBox.critical(self, "Acesso Negado", "Falta de privilégios de administrador (Código 5).")
            elif rc == 1223 or rc == 0:
                QMessageBox.warning(self, "Cancelado", "A operação foi cancelada no prompt do UAC.")
            else:
                QMessageBox.warning(self, "Erro",
                                    f"Falha ao iniciar o helper RAW como administrador. Código retornado: {rc}")
            return

        self._raw_tempo_inicio = time.time()
        self._raw_timer = QTimer(self)
        self._raw_timer.timeout.connect(self._poll_raw_hash_status)
        self._raw_timer.start(INTERVALO_ATUALIZACAO_BARRA_PREVISAO_PROGRESSO_TOTAL * 1000)


    def _poll_raw_hash_status(self):
        QApplication.processEvents() # Permite que o programa registre o clique no botão "Cancelar"
        # 1) Progresso
        try:
            if hasattr(self, "_raw_progress_json") and os.path.exists(self._raw_progress_json):
                with open(self._raw_progress_json, "r", encoding="utf-8") as f:
                    p = json.load(f)
                pct = int(p.get("percent", 0))
                self.barra_arquivo.setValue(max(0, min(100, pct)))
                self.barra_total.setValue(max(0, min(100, pct)))

                bytes_read = p.get("bytes_read", 0)
                bytes_total = p.get("bytes_total", 0)

                fmt_lidos = formatar_bytes_dinamico(bytes_read)
                fmt_total = formatar_bytes_dinamico(bytes_total)
                self.lbl_progresso_arquivo.setText(f"RAW {pct}% ({fmt_lidos} / {fmt_total}) - {self._raw_device}")

                if hasattr(self, "_raw_tempo_inicio"):
                    import time  # Certifique-se de que time está importado no topo do arquivo
                    decorrido = time.time() - self._raw_tempo_inicio

                    # Formata o tempo decorrido
                    horas_d, rem_d = divmod(decorrido, 3600)
                    mins_d, segs_d = divmod(rem_d, 60)
                    str_decorrido = f"{int(horas_d):02d}:{int(mins_d):02d}:{int(segs_d):02d}"

                    # Calcula o tempo restante
                    if bytes_read > 0 and decorrido > 0:
                        bytes_por_segundo = bytes_read / decorrido
                        bytes_restantes = bytes_total - bytes_read

                        restante = bytes_restantes / bytes_por_segundo if bytes_por_segundo > 0 else 0

                        horas_r, rem_r = divmod(restante, 3600)
                        mins_r, segs_r = divmod(rem_r, 60)
                        str_restante = f"{int(horas_r):02d}:{int(mins_r):02d}:{int(segs_r):02d}"
                    else:
                        str_restante = "Calculando..."

                    self.lbl_progresso_total.setText(
                        f"Progresso RAW ({fmt_lidos} / {fmt_total}) - Decorrido: {str_decorrido} | Restante: {str_restante}"
                    )
        except Exception:
            pass

        # 2) Final
        if os.path.exists(self._raw_out_json):
            try:
                with open(self._raw_out_json, "r", encoding="utf-8") as f:
                    payload = json.load(f)
            except Exception as e:
                payload = {"ok": False, "error": f"Falha ao ler JSON final: {e}"}

            self._raw_timer.stop()

            self.btn_cancelar.setEnabled(False)
            self.btn_cancelar.setText("CANCELAR PROCESSAMENTO")

            self.texto_saida.append("=== HASH RAW (BIT-A-BIT) ===")
            if hasattr(self, '_raw_metodo_escolhido'):
                self.texto_saida.append(f"Metodologia: {self._raw_metodo_escolhido}")
            self.texto_saida.append(f"Dispositivo: {self._raw_device}")

            if hasattr(self, '_raw_caminho_imagem') and self._raw_caminho_imagem:
                self.texto_saida.append(f"Imagem gerada: {self._raw_caminho_imagem}")

            if payload.get("ok"):
                res = payload.get("result", {})
                b_lidos = res.get('bytes_read', 0)
                b_total = res.get('bytes_total', 0)

                # Traduz os bytes usando a nova função
                fmt_lidos = formatar_bytes_dinamico(b_lidos)
                fmt_total = formatar_bytes_dinamico(b_total)

                # Exibe o valor bruto e o formatado ao lado
                str_bytes = f"Bytes lidos: {b_lidos} / {b_total} ({fmt_lidos} / {fmt_total})"
                self.texto_saida.append(str_bytes)

                hashes = res.get("hashes", {})
                texto_hashes = []
                for k, v in hashes.items():
                    texto_hashes.append(f"{k}: {v}")
                    self.texto_saida.append(f"{k}: {v}")

                # --- INTEGRAÇÃO: VALIDAÇÃO DA CADEIA DE CUSTÓDIA PARA RAW ---
                texto_custodia = self.texto_referencia.toPlainText().strip()
                if texto_custodia:
                    validador_raw = ValidadorCustodia(texto_custodia)
                    status, msg_custodia = validador_raw.validar_hash_simples(hashes)

                    self.texto_saida.append("")
                    texto_hashes.append("")

                    # ========================================================
                    # INSERE A LISTA ORIGINAL (Igual ao fluxo de arquivos)
                    # ========================================================
                    nome_ref = getattr(self.texto_referencia, 'nome_arquivo_origem', None)
                    hash_ref = getattr(self.texto_referencia, 'hash_arquivo_origem', None)

                    if nome_ref and hash_ref:
                        cabecalho_ref = f"=== RELAÇÃO ORIGINAL DE HASHES (Extraída de: {nome_ref} - SHA-256: {hash_ref}) ==="
                    elif nome_ref:
                        cabecalho_ref = f"=== RELAÇÃO ORIGINAL DE HASHES (Extraída de: {nome_ref}) ==="
                    else:
                        cabecalho_ref = "=== RELAÇÃO ORIGINAL DE HASHES (CADEIA DE CUSTÓDIA) ==="

                    self.texto_saida.append(cabecalho_ref)
                    texto_hashes.append(cabecalho_ref)

                    lista_referencia = validador_raw.obter_lista_limpa()
                    for item in lista_referencia:
                        self.texto_saida.append(item)
                        texto_hashes.append(item)

                    self.texto_saida.append("-" * 60)
                    texto_hashes.append("-" * 60)
                    # ========================================================

                    self.texto_saida.append("=== RESULTADO DA VALIDAÇÃO ===")
                    self.texto_saida.append(msg_custodia)
                    self.texto_saida.append("")

                    # Adiciona a validação à lista de textos que vão para o Log físico (txt)
                    texto_hashes.append("=== RESULTADO DA VALIDAÇÃO ===")
                    texto_hashes.append(msg_custodia)
                # ------------------------------------------------------------

                # Escreve o arquivo de auditoria físico (.txt)
                if hasattr(self, '_caminho_audit_log') and self._caminho_audit_log:
                    try:
                        with open(self._caminho_audit_log, "w", encoding="utf-8") as f_log:
                            f_log.write("=" * 55 + "\n")
                            f_log.write(f"LOG DE AUDITORIA FORENSE - {NOME_APP} - versão {VERSAO_APP}\n")
                            f_log.write("=" * 55 + "\n\n")
                            f_log.write(
                                f"Data/Hora Conclusão: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")

                            if hasattr(self, '_raw_metodo_escolhido'):
                                f_log.write(f"Metodologia: {self._raw_metodo_escolhido}\n")

                            f_log.write(f"Alvo da Extração: {self._raw_device}\n")

                            if hasattr(self, '_raw_caminho_imagem') and self._raw_caminho_imagem:
                                f_log.write(f"Imagem gerada: {self._raw_caminho_imagem}\n")

                            f_log.write(f"{str_bytes}\n\n")
                            f_log.write("CADEIA DE CUSTÓDIA - HASHE(S) DA IMAGEM:\n")
                            for linha in texto_hashes:
                                f_log.write(f" -> {linha}\n")
                            f_log.write("\n" + "=" * 55 + "\n")
                    except Exception as e:
                        self.texto_saida.append(f"\nERRO: Falha ao gerar arquivo de auditoria físico: {e}")
            else:
                self.texto_saida.append(f"ERRO: {payload.get('error')}")

            self.texto_saida.append("")
            self._desativar_modo_admin_visual()
            self.destravar_interface()
            self.barra_arquivo.setValue(100)
            self.barra_total.setValue(100)
            self.lbl_progresso_arquivo.setText("Progresso do Arquivo Atual: Concluído!")
            self.lbl_progresso_total.setText("Progresso RAW - Concluído!")

            self._salvar_relatorio_automatico()

            # --- LIMPEZA DO DIRETÓRIO TEMPORÁRIO ---
            try:
                diretorio_temp = os.path.dirname(self._raw_out_json)
                if os.path.exists(diretorio_temp):
                    shutil.rmtree(diretorio_temp, ignore_errors=True)
                    if DEBUG_MESSAGES:
                        print(f"[DEBUG] Diretório temporário apagado: {diretorio_temp}")
            except Exception as e:
                if DEBUG_MESSAGES:
                    print(f"[DEBUG] Falha ao tentar apagar diretório temporário: {e}")
            # ---------------------------------------------

    def acao_cancelar(self):
        self.cancelar_operacao = True
        self.btn_cancelar.setText("CANCELANDO PROCESSAMENTO...")
        self.btn_cancelar.setEnabled(False)

        # Força o cancelamento imediato dentro da Thread
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.cancelar_operacao = True

        QApplication.processEvents()

        # Verifica se está em um processo de RAW Hash
        caminho_flag = getattr(self, "_raw_cancel_flag", None)
        if caminho_flag:
            if DEBUG_MESSAGES:
                print(f"[DEBUG] Tentando cancelar o RAW Hash. Caminho da flag: {caminho_flag}")

            try:
                # 1. Garante que o diretório exista
                os.makedirs(os.path.dirname(caminho_flag), exist_ok=True)

                # 2. Cria o arquivo forçando o modo de escrita 'w'
                with open(caminho_flag, "w", encoding="utf-8") as f:
                    f.write("CANCELAR")
                    f.flush()
                    os.fsync(f.fileno())  # Força sincronização de disco

                if DEBUG_MESSAGES:
                    print(f"[DEBUG] Arquivo flag criado fisicamente em: {caminho_flag}")
            except Exception as e:
                print(f"[ERRO CRÍTICO] Falha ao escrever flag de cancelamento: {e}")
                import traceback
                traceback.print_exc()
        else:
            if DEBUG_MESSAGES:
                print("[DEBUG] Nenhuma operação RAW em andamento para cancelar.")

    def salvar_estado_atual(self, *args):
        """Salva as configurações atuais imediatamente após qualquer alteração."""
        config = {
            'chk_modo_escuro': self.chk_modo_escuro.isChecked(),
            'chk_metadados': self.chk_metadados.isChecked(),
            'chk_metadados_raw': self.chk_metadados_raw.isChecked(),
            'chk_subdiretorios': self.chk_subdiretorios.isChecked(),
            'hashes': {algo: chk.isChecked() for algo, chk in self.chk_hashes.items()}
        }
        salvar_config(config)

    def closeEvent(self, event):
        """Intercepta o fechamento, alerta sobre o Write-Blocker, salva as configurações e limpa rastros."""

        # ==========================================================
        # 1. VERIFICAÇÃO DO WRITE-BLOCKER ANTES DE FECHAR
        # ==========================================================
        if hasattr(self, '_verificar_status_wb') and self._verificar_status_wb():
            msg = QMessageBox(self)
            msg.setWindowTitle("Aviso Forense - Bloqueio de USB Ativo")
            msg.setIcon(QMessageBox.Icon.Warning)

            # --- Ajusta a cor do vermelho dinamicamente baseando-se no tema ---
            is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
            cor_alerta = "#ff5555" if is_dark else "#cc0000"

            # Injeta a cor correta na tag HTML
            msg.setText(f"<h3 style='margin: 0; color: {cor_alerta};'>O Bloqueio de Escrita USB ainda está ATIVO!</h3>")

            msg.setInformativeText(
                "<div style='font-size: 11pt;'>"
                "<p>Se você fechar o programa agora, o computador <b>continuará bloqueando</b> a gravação em pendrives e HDs externos.</p>"
                "<p>O que você deseja fazer?</p>"
                "</div>"
            )

            # Cria botões com as opções
            btn_desbloquear = msg.addButton("Desbloquear Escrita em USB\ne fechar o programa",
                                            QMessageBox.ButtonRole.ActionRole)
            btn_manter = msg.addButton("Manter Bloqueio de Escrita em USB\ne fechar o programa",
                                       QMessageBox.ButtonRole.ActionRole)
            btn_cancelar = msg.addButton("Cancelar fechamento\ndo programa",
                                         QMessageBox.ButtonRole.RejectRole)

            msg.exec()

            # --- AVALIA A ESCOLHA DO USUÁRIO ---
            if msg.clickedButton() == btn_cancelar:
                # O usuário desistiu de fechar. Ignoramos o evento e abortamos o processo de fechamento.
                event.ignore()
                return

            elif msg.clickedButton() == btn_desbloquear:
                # O usuário quer desbloquear antes de fechar. Disparamos a rotina via UAC.
                sucesso = self._desbloquear_ao_fechar()
                if not sucesso:
                    # Falhou no UAC, não deixa o programa fechar para não perder o controle do bloqueio
                    event.ignore()
                    return

            # Se ele clicou em "Manter Bloqueado e Fechar", o fluxo simplesmente continua para a etapa 2.

        # ==========================================================
        # 2. ROTINA ORIGINAL DE FECHAMENTO (SÓ RODA SE ELE DECIDIR FECHAR)
        # ==========================================================

        # Usa a função centralizada de salvamento de configurações
        if hasattr(self, 'salvar_estado_atual'):
            self.salvar_estado_atual()

        # --- LIMPEZA DE RASTROS AO FECHAR ---
        if hasattr(self, 'limpar_arquivos_temporarios'):
            self.limpar_arquivos_temporarios()

        event.accept()

    def _desbloquear_ao_fechar(self):
        """Executa a rotina de desbloqueio com UAC focada no encerramento do programa."""
        import subprocess

        argumentos_reg = "add HKLM\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies /v WriteProtect /t REG_DWORD /d 0 /f"
        comando = [
            "powershell",
            "-NoProfile",
            "-WindowStyle", "Hidden",
            "-Command",
            f"Start-Process -FilePath 'reg.exe' -ArgumentList '{argumentos_reg}' -Verb RunAs -WindowStyle Hidden -Wait"
        ]

        try:
            # Chama o UAC do Windows para a alteração
            subprocess.run(comando, creationflags=0x08000000)

            # Verifica se deu certo
            status_atualizado = self._verificar_status_wb()

            if status_atualizado == False:  # False = 0 (Desbloqueado com sucesso)
                return True
            else:
                msg_erro = QMessageBox(self)
                msg_erro.setWindowTitle("Falha no Desbloqueio")
                msg_erro.setIcon(QMessageBox.Icon.Warning)
                msg_erro.setText("<h3 style='margin: 0; color: #cc6600;'>O registro NÃO foi alterado.</h3>")
                msg_erro.setInformativeText(
                    "<div style='font-size: 11pt;'>"
                    "<p>A autorização do Windows (UAC) foi cancelada, as credenciais estão incorretas ou há um <b>bloqueio silencioso de TI (GPO)</b> para usuários padrão.</p>"
                    "<p><b>O programa não será fechado</b> para que você possa tentar novamente.</p>"
                    "</div>"
                )
                msg_erro.exec()
                return False

        except Exception as e:
            QMessageBox.critical(self, "Erro Forense", f"Falha ao tentar desbloquear durante o fechamento: {e}")
            return False

    def limpar_arquivos_temporarios(self):
        """
        Varre a pasta Temp do Windows, cria flags de cancelamento e remove diretórios órfãos.
        Remove apenas temporários RAW antigos (>24h). NÃO cancela operações ativas.
        """
        try:
            diretorio_temp_so = tempfile.gettempdir()
            agora = time.time()
            limite = 24 * 3600  # 24h

            for item in os.listdir(diretorio_temp_so):
                if not item.startswith("ERS_IC_NIC_RAW_"):
                    continue

                caminho_completo = os.path.join(diretorio_temp_so, item)
                if not os.path.isdir(caminho_completo):
                    continue

                try:
                    mtime_dir = os.path.getmtime(caminho_completo)
                except Exception:
                    continue

                # Só apaga se for claramente "órfão/antigo"
                if (agora - mtime_dir) > limite:
                    shutil.rmtree(caminho_completo, ignore_errors=True)
        except Exception as e:
            if DEBUG_MESSAGES:
                print(f"[DEBUG] Erro ao executar limpeza global de temporários: {e}")

    def eventFilter(self, obj, event):
        eh_alvo = False

        # 1. Verifica de forma segura o componente que disparou o evento
        if hasattr(self, 'lbl_alerta_versao') and obj == self.lbl_alerta_versao:
            eh_alvo = True
        elif hasattr(self, 'chk_metadados') and obj == self.chk_metadados:
            eh_alvo = True
        elif hasattr(self, 'chk_metadados_raw') and obj == self.chk_metadados_raw:
            eh_alvo = True
        elif hasattr(self, 'chk_hashes') and obj in self.chk_hashes.values():
            eh_alvo = True
        elif hasattr(self, 'btn_manual_online') and obj == self.btn_manual_online:
            eh_alvo = True
        elif hasattr(self, 'btn_sobre') and obj == self.btn_sobre:
            eh_alvo = True
        elif hasattr(self, 'btn_unidade_raw') and obj == self.btn_unidade_raw:
            eh_alvo = True

        if eh_alvo:
            # 2. Quando o mouse ENTRA (Ação imediata)
            if event.type() == QEvent.Type.Enter:
                from PySide6.QtGui import QCursor

                pos_mouse = QCursor.pos()

                # A) Se for o Tooltip de Nova Versão, exibe o HTML customizado e empurra MUITO pra esquerda
                if hasattr(self, 'lbl_alerta_versao') and obj == self.lbl_alerta_versao and hasattr(
                        self.lbl_alerta_versao, 'custom_tooltip_text'):
                    pos_mouse.setX(pos_mouse.x() - 500)
                    pos_mouse.setY(pos_mouse.y() + 15)
                    QToolTip.showText(pos_mouse, self.lbl_alerta_versao.custom_tooltip_text, obj)
                    return True

                # B) Se for o tooltip GIGANTE de Metadados (Básico ou RAW), empurra um pouco pra esquerda
                elif (hasattr(self, 'chk_metadados') and obj == self.chk_metadados) or \
                        (hasattr(self, 'chk_metadados_raw') and obj == self.chk_metadados_raw):
                    pos_mouse.setX(pos_mouse.x() - 320)
                    pos_mouse.setY(pos_mouse.y() + 15)
                    QToolTip.showText(pos_mouse, obj.toolTip(), obj)
                    return True

                # C) Se for os de Hashes (menores), deixa perto do mouse e para a direita
                else:
                    pos_mouse.setX(pos_mouse.x() + 15)
                    pos_mouse.setY(pos_mouse.y() + 15)
                    QToolTip.showText(pos_mouse, obj.toolTip(), obj)
                    return True

            # 3. Quando o mouse SAI
            elif event.type() == QEvent.Type.Leave:
                QToolTip.hideText()
                return True

            # 4. Ignora o delay padrão do Windows
            elif event.type() == QEvent.Type.ToolTip:
                return True

        # Para todos os outros botões e eventos de tela, segue o comportamento normal
        return super().eventFilter(obj, event)

    def mostrar_sobre(self):
        dialog = QDialog(self)
        dialog.setWindowTitle(F"Funcionalidades Forenses, Licença e Termos de Uso - {NOME_APP} - v.{VERSAO_APP}")
        dialog.resize(800, 680)

        layout_principal = QVBoxLayout()

        # --- CABEÇALHO: ÍCONE + INFOS BÁSICAS (Fora das abas, visível sempre) ---
        layout_cabecalho = QHBoxLayout()

        # 1. Ícone do App - Usando QIcon para evitar desfoque
        lbl_icone = QLabel()
        if os.path.exists(ICON_PATH):
            # QIcon.pixmap busca a maior resolução no .ico para reduzir com qualidade
            pixmap = QIcon(ICON_PATH).pixmap(80, 80)
            lbl_icone.setPixmap(pixmap)
        layout_cabecalho.addWidget(lbl_icone)
        layout_cabecalho.addSpacing(20)

        # --- Cor dinâmica para os links ---
        is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
        cor_link = "#66b2ff" if is_dark else "#0056b3"

        # 2. Informações principais: Nome, Versão, Desenvolvedor e Contato
        lbl_infos_topo = QLabel(
            f"<div style='line-height: 140%;'>"
            f"<h2 style='margin-bottom: 2px;'>{NOME_APP}</h2>"
            f"<b>Versão:</b> {VERSAO_APP}<br>"
            f"<b>Desenvolvedor:</b> {DESENVOLVEDOR}<br>"
            f"<b>Contato / Reportar Bugs:</b> <a href='mailto:{EMAIL_CONTATO}' style='color: {cor_link};'>{EMAIL_CONTATO}</a><br>"
            f"<b>Projeto e Atualizações:</b> <a href='{LINK_GITHUB}' style='color: {cor_link};'>Repositório no GitHub</a>"
            f"</div>"
        )
        lbl_infos_topo.setOpenExternalLinks(True)
        layout_cabecalho.addWidget(lbl_infos_topo)
        layout_cabecalho.addStretch()
        layout_principal.addLayout(layout_cabecalho)

        # Linha Divisória
        linha = QFrame()
        linha.setFrameShape(QFrame.Shape.HLine)
        linha.setFrameShadow(QFrame.Shadow.Sunken)
        layout_principal.addWidget(linha)

        # --- SISTEMA DE ABAS ---
        abas = QTabWidget()
        layout_principal.addWidget(abas)

        # ==============================================================
        # ABA 1: FUNCIONALIDADES E SEGURANÇA FORENSE (O SEU CÓDIGO ORIGINAL)
        # ==============================================================
        aba_sobre = QWidget()
        layout_sobre = QVBoxLayout(aba_sobre)
        layout_sobre.setContentsMargins(0, 0, 0, 0)  # Tira as bordas internas duplas

        # CORPO: TEXTO TÉCNICO COM ROLAGEM
        texto_sobre = QTextEdit()
        texto_sobre.setReadOnly(True)
        if self.chk_modo_escuro.isChecked():
            texto_sobre.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; font-size: 10pt; border: none;")
        else:
            texto_sobre.setStyleSheet("background-color: #ffffff; color: #111111; font-size: 10pt; border: none;")

        # Descrição geral das funcionalidades da versão
        conteudo_html = (
            "<p>Ferramenta pericial desenvolvida para extração rápida de hashes criptográficos e metadados de uma vasta gama de arquivos, "
            "além de permitir a <b>Aquisição Forense (Bit-a-bit)</b> de unidades lógicas e físicas, incluindo:</p>"
            "<ul>"
            "<li>Imagens, Áudios e Vídeos (Nativos e RAW)</li>"
            "<li>Documentos (PDF, Pacote Office, RTF)</li>"
            "<li>Executáveis e Atalhos do Windows (LNK)</li>"
            "<li>E-mails Exportados (EML, MSG)</li>"
            "<li>Arquivos Compactados (ZIP, RAR, 7Z) e Torrents</li>"
            "<li>Arquivos Geográficos / Mapas (KML, KMZ, GPX, XML)</li>"
            "</ul>"
            "<p><i>Dica: Para visualizar a lista exata de todas as extensões analisadas, clique no botão <b>'Formatos Suportados'</b> na tela inicial.</i></p>"

            "<h3>🛡️ Segurança e Integridade Forense (Software Read-Only):</h3>"
            "<ul>"
            "<li><b>Acesso em Nível de Kernel:</b> Nas operações RAW, o software utiliza a flag <i>GENERIC_READ</i> da API do Windows, solicitando ao sistema operacional acesso estrito de leitura.</li>"
            "<li><b>Escrita Zero:</b> O software opera de forma estritamente unidirecional, sem enviar comandos de gravação ao dispositivo. Ressalta-se que esta proteção lógica padrão <b>não substitui</b> o bloqueio de escrita (ver seção <i>Software Write-Blocker</i> abaixo) para assegurar a integridade da prova contra alterações do sistema operacional.</li>"
            "<li><b>File Lock:</b> Arquivos individuais são travados durante a leitura (MSVCRT Locking) para evitar corrupção ou alteração do hash por processos paralelos.</li>"
            "<li><b>Detecção de Arquivos em Uso:</b> Tratamento seguro de exceções de permissão e travas do sistema, diferenciando arquivos abertos para leitura daqueles trancados exclusivamente pelo S.O.</li>"
            "<li><b>Isolamento de Nuvem (Anti-Download):</b> Detecta e bloqueia a leitura de arquivos 'Apenas Online' (OneDrive/Google Drive) marcados com <i>Recall on Data Access</i>, evitando alteração da evidência local e tráfego de rede.</li>"
            "<li><b>Seleção Literal (Anti-Redirecionamento):</b> A interface ignora as resoluções nativas do Windows para Links Simbólicos, Junções de Diretório e Atalhos, garantindo o hash estrito do item selecionado.</li>"
            "<li><b>Detecção de Arquivos Vazios:</b> Reconhecimento automático de hashes universalmente conhecidos (0 bytes) para todos os algoritmos.</li>"
            "<li><b>Tratamento Transparente de Erros:</b> Diferencia claramente bibliotecas ausentes, arquivos corrompidos e metadados intencionalmente removidos.</li>"
            "</ul>"
            
            "<h3>🛑 Software Write-Blocker (Proteção de Escrita USB):</h3>"
            "<ul>"
            "<li><b>Bloqueio via Registro do Windows:</b> Altera as políticas de armazenamento do sistema operacional (<i>StorageDevicePolicies</i>) para impedir a gravação de dados, indexação indesejada ou criação de arquivos ocultos (como o <i>System Volume Information</i>) em mídias USB.</li>"
            "<li><b>Protocolo de Ativação:</b> Para garantir a inalterabilidade da evidência, o bloqueio deve ser ativado rigorosamente <b>antes</b> da conexão do pendrive ou HD externo à máquina. Dispositivos que já estiverem plugados durante a ativação não estarão protegidos.</li>"
            "<li><b>Elevação de Privilégio Sob Demanda (UAC):</b> A alteração da política exige direitos de Administrador. O programa solicita essa elevação de forma isolada e segura apenas para a execução do comando no registro (via <i>reg.exe</i>), mantendo a interface principal rodando no escopo do usuário padrão.</li>"
            "<li><b>Aviso Pericial (Valor Probatório vs. Padrão-Ouro):</b> O bloqueio lógico via software é um método seguro e com <b>pleno valor probatório</b> para a preservação de evidências, desde que o protocolo de ativação seja rigorosamente seguido. Contudo, as diretrizes forenses internacionais mantêm o <b>Hardware Write-Blocker (Bloqueador Físico)</b> como o verdadeiro <b>Padrão-Ouro</b>, pois, ao atuar na camada física, ele elimina os riscos de eventuais falhas de procedimento e/ou instabilidades do Sistema Operacional.</li>"
            "</ul>"

            "<h3>💾 Aquisição RAW e Imagem Forense (.dd ou .e01):</h3>"
            "<ul>"
            "<li><b>Extração Setor-por-Setor:</b> Realiza a leitura sequencial completa da mídia, capturando dados ativos, remanescentes em espaços não alocados (Unallocated Space) e artefatos de arquivos deletados.</li>"
            "<li><b>Integridade On-the-Fly:</b> O cálculo dos hashes selecionados ocorre simultaneamente à leitura e gravação, garantindo a autenticidade da evidência sem a necessidade de reprocessamento da imagem gerada.</li>"
            "<li><b>Mapeamento de Hardware:</b> Capacidade de aquisição de discos físicos inteiros (incluindo tabelas MBR/GPT) ou volumes lógicos específicos, permitindo flexibilidade conforme a estratégia pericial.</li>"
            "<li><b>Documentação de Custódia:</b> Registro automático de metadados do hardware de origem e logs de auditoria detalhados para fundamentar a preservação da evidência em relatórios oficiais.</li>"
            "<li><b>Diagnóstico de Baixo Nível:</b> Sistema de tradução de códigos de erro do Windows para identificação clara de falhas físicas (como erros de CRC ou I/O) durante o processo de extração.</li>"
            "</ul>"

            "<h3>🔍 Análises Forenses Integradas:</h3>"
            "<ul>"
            "<li><b>Extração Profunda de Mídia:</b> Usa múltiplas engines em cascata (pymediainfo, ExifTool, OpenCV, TinyTag) para vasculhar dados de geolocalização com links para mapas, resoluções internas e indícios de edição via software (iMovie, Adobe Premiere etc.). Especial destaque para a Análise Avançada de FPS em vídeos, que identifica vídeos gravados com Taxa de Quadros Variável (VFR), extraindo as taxas nominal, mínima e máxima direto dos cabeçalhos, além de cruzar a contagem de quadros físicos com a duração em milissegundos para obter a taxa média real do arquivo. Para vídeos, o ExifTool extrai adicionalmente GPS embutido, data/hora de criação real, fuso horário, marca e modelo do dispositivo, software de edição, rotação, UUID de gravação (ContentIdentifier), número de série de câmeras profissionais e drones, telemetria de drone, indícios de câmeras de vigilância/DVR e detecção de remoção intencional de metadados (metadata stripping). O MediaInfo complementa com trilha General (container, bitrate global, data de codificação/gravação), trilha de áudio (codec, canais, sample rate, bitrate), formato do codec de vídeo, colorimetria, tipo de varredura e campos customizados de fabricante (Android, Xiaomi, DJI, Hikvision, Dahua etc.).</li>"
            "<li><b>Perícia Avançada em Vídeos:</b> Além da Análise de FPS Variável (VFR), a ferramenta agora extrai as Razões de Proporção (DAR/PAR) traduzidas para formatos visuais (16:9, 4:3, Vertical), identifica pixels anamórficos, evidencia discrepâncias entre a resolução de exibição e a resolução armazenada (codificada) e detecta se o vídeo possui espelhamento horizontal ou vertical via matriz de transformação.</li>"
            "<li><b>Extração Completa (Raw Dump):</b> Opção avançada na interface gráfica que permite exportar e anexar o dicionário bruto e integral de todas as bibliotecas de análise subjacentes ao final de cada arquivo, garantindo que o perito tenha acesso a metadados exóticos ou proprietários não listados no resumo básico.</li>"
            "<li><b>Detecção de Lavagem de Metadados (Metadata Stripping):</b> Análise heurística que identifica padrões de nomes de arquivos gerados pelo WhatsApp, Telegram, Instagram, Facebook e Twitter, emitindo alertas sobre metadados originais destruídos pela plataforma.</li>"
            "<li><b>Detecção NTFS ADS:</b> Varredura automática e em profundidade por Alternate Data Streams (dados ocultos em partições NTFS), identificando <i>Mark of the Web</i> e gerando comandos de extração para o PowerShell caso payloads maliciosos grandes sejam detectados.</li>"
            "<li><b>Entropia de Shannon:</b> Cálculo de aleatoriedade para detecção de arquivos criptografados, compactados ou ofuscados (Packed).</li>"
            "<li><b>Detecção de Arquivos Duplicados (Triagem Otimizada):</b> Identifica e agrupa automaticamente arquivos idênticos processados em lote. O motor de comparação prioriza o cruzamento de algoritmos criptográficos robustos (como SHA-256 e SHA-512), utilizando o CRC32 apenas como recurso final na ausência destes, o que garante alta precisão técnica e mitiga o risco de falsos positivos por colisão.</li>"
            "<li><b>Metadados Avançados e Dados Espaciais:</b> Extração de coordenadas GPS (com links para mapas), datas internas de criação, marcas de dispositivos e rastreios de autoria/edição. Inclui botões para geração de arquivos KML com exportação de perímetros geográficos (Polígonos e Pontos).</li>"
            "<li><b>Validação de Assinatura e Binários:</b> Checagem de certificados Authenticode em executáveis (EXE/DLL/SYS) e extração do Data/Hora exata de compilação registrada no cabeçalho PE.</li>"
            "</ul>"
            
            "<h3>🔗 Validação Automática da Cadeia de Custódia:</h3>"
            "<ul>"
            "<li><b>Conferência de Listagens de Hashes:</b> Permite o <i>Drag & Drop</i> (arrastar e soltar) de laudos e listagens de hashes de origem (nos formatos PDF, DOCX, XLSX, TXT) ou inserção de texto livre, para auditar a extração feita pelo responsável pela coleta original dos dados e preservar intacta a Cadeia de Custódia.</li>"
            "<li><b>Limpeza Forense de Texto:</b> Motor de extração blindado contra sujeiras de formatação e artefatos visuais de PDFs (como espaços invisíveis e quebras de linha fantasmas), garantindo a leitura exata do nome e do hash.</li>"
            "<li><b>Busca Heurística Inteligente:</b> O algoritmo rastreia o texto (na mesma linha ou em linhas anteriores) para associar o hash ao nome correto do arquivo. Exclusivamente para laudos em PDF, a ferramenta aciona uma busca bidirecional (progressiva) para compensar quebras irregulares de página, sempre utilizando 'barreiras de algoritmo' para evitar falsos positivos.</li>"
            "<li><b>Rastreabilidade (A Prova da Prova):</b> Ao arrastar um arquivo de referência, a ferramenta calcula e registra no relatório final o hash SHA-256 do próprio documento utilizado para a conferência, amarrando a auditoria.</li>"
            "<li><b>Alerta de CRC32:</b> Hashes CRC32 eventualmente presentes nos laudos de referência são intencionalmente ignorados no cruzamento de dados para evitar falsos positivos (por colidirem com datas ou números sequenciais em texto plano).</li>"
            "</ul>"

            "<h3>🔓 Transparência, Velocidade e Auditoria:</h3>"
            "<ul>"
            "<li><b>Compilação em Código Nativo:</b> Graças ao backend em C, os tempos de leitura em lote e cálculo de hashes simultâneos são rigorosamente mais rápidos que aplicações comuns.</li>"
            "<li><b>Atualizações Seguras:</b> Conta com uma rotina em thread separada que comunica-se passivamente com a API do GitHub apenas para alertar o analista sobre novas versões, preservando a estabilidade da interface principal.</li>"
            "<li><b>Código Aberto:</b> Em conformidade com as boas práticas forenses, o algoritmo de processamento é aberto para auditoria através do botão 'Baixar Código Fonte para Auditoria (.py)' abaixo.</li>"
            f"<li><b>Assinatura Digital do Código (SHA-256):</b> Este hash valida a integridade do arquivo 'extrator_hashes_metadados.py' incluído neste pacote (mesmo usado para a compilação desta versão {VERSAO_APP}).<br>"
            f"<code style='color: #d9534f; background-color: #f9f2f4; padding: 2px 4px; border-radius: 4px; font-family: Consolas;'>{HASH_DO_CODIGO_FONTE}</code></li>"
            "</ul>"

            "<h3>💻 Comandos Internos (Under the Hood):</h3>"
            "<p>Para fins de reprodutibilidade e auditoria pericial, abaixo estão as chamadas exatas de linha de comando (CLI) executadas pelo sistema em segundo plano:</p>"
            
            "<b>1. Extração de Metadados via ExifTool:</b>"
            "<div style='background-color: #2b2b2b; color: #f0f0f0; padding: 6px; border-radius: 4px; font-family: Consolas, monospace; margin-top: 5px; margin-bottom: 5px;'>"
            "exiftool -charset filename=latin -charset utf8 -j -G -a -ee -api largefilesupport=1 -c \"%+.6f\" \"evidencia.ext\""
            "</div>"
            "<ul>"
            "<li><b>-charset:</b> Força a leitura correta de caminhos e nomes com caracteres latinos.</li>"
            "<li><b>-j:</b> Retorna a saída formatada nativamente em JSON para análise segura.</li>"
            "<li><b>-G:</b> Imprime o grupo estrutural ao qual o metadado pertence.</li>"
            "<li><b>-a:</b> Permite a extração de tags duplicadas (ex: trilhas de vídeo múltiplas).</li>"
            "<li><b>-ee:</b> Extrai informações embutidas (vital para geolocalização dinâmica de drones/GoPros).</li>"
            "<li><b>-api largefilesupport=1:</b> Habilita suporte a arquivos maiores que 4 GB.</li>"
            "<li><b>-c \"%+.6f\":</b> Padroniza as coordenadas geográficas em graus decimais.</li>"
            "</ul>"

            "<b>2. Aquisição de Imagem Forense (.E01) via libewf (ewfacquire):</b>"
            "<div style='background-color: #2b2b2b; color: #f0f0f0; padding: 6px; border-radius: 4px; font-family: Consolas, monospace; margin-top: 5px; margin-bottom: 5px;'>"
            "ewfacquire -u -c fast -t \"destino\" -l \"destino.ewf.log\" -d sha256 -S 4G -C \"Operação\" -E \"Laudo\" \"\\\\.\\PhysicalDrive0\""
            "</div>"
            "<ul>"
            "<li><b>-u:</b> Modo não-interativo (unattended).</li>"
            "<li><b>-c fast:</b> Define o nível de compressão do contêiner EWF.</li>"
            "<li><b>-t / -l:</b> Caminho alvo e caminho exato para a escrita espelhada do log de auditoria.</li>"
            "<li><b>-d sha256:</b> Força a injeção do hash SHA-256 no cabeçalho interno dos blocos.</li>"
            "<li><b>-S / -C / -E:</b> Argumentos dinâmicos preenchidos através da janela 'Cabeçalho Forense'.</li>"
            "</ul>"

            "<b>3. Verificação de Integridade Criptográfica (ewfverify):</b>"
            "<div style='background-color: #2b2b2b; color: #f0f0f0; padding: 6px; border-radius: 4px; font-family: Consolas, monospace; margin-top: 5px; margin-bottom: 10px;'>"
            "ewfverify -d md5,sha256 \"caminho_destino.e01\""
            "</div>"
            "<p>Valida os hashes gravados dentro do contêiner para atestar que a imagem não sofreu corrupção durante a operação de cópia do sistema operacional.</p>"

            "<h3>⚙️ Requisitos de Sistema:</h3>"
            "<ul>"
            "<li><b>Arquitetura:</b> Exclusivo para Windows 64-bits (x64). Sistemas 32-bits (x86) não são suportados devido a limitações de endereçamento de memória na aquisição forense RAW.</li>"
            "<li><b>Privilégios:</b> Execução padrão como Usuário Comum. Privilégios de Administrador (UAC) são solicitados sob demanda apenas durante a extração de discos físicos.</li>"
            "</ul>"
        )

        texto_sobre.setHtml(conteudo_html)
        layout_sobre.addWidget(texto_sobre)
        abas.addTab(aba_sobre, "Funcionalidades Forenses")

        # ==============================================================
        # ABA 2: TERMOS DE USO E LICENÇA
        # ==============================================================
        aba_licenca = QWidget()
        layout_licenca = QVBoxLayout(aba_licenca)
        layout_licenca.setContentsMargins(0, 0, 0, 0)

        texto_licenca_ui = QTextEdit()
        texto_licenca_ui.setPlainText(TEXTO_LICENCA)  # A variável global criada antes
        texto_licenca_ui.setReadOnly(True)

        # Um fundo ligeiramente diferente para destacar que é um documento legal
        if self.chk_modo_escuro.isChecked():
            texto_licenca_ui.setStyleSheet(
                "background-color: #1e1e1e; color: #d4d4d4; font-family: Consolas, monospace; font-size: 10pt; border: none; padding: 10px;")
        else:
            texto_licenca_ui.setStyleSheet(
                "background-color: #f8f9fa; color: #333; font-family: Consolas, monospace; font-size: 10pt; border: none; padding: 10px;")

        layout_licenca.addWidget(texto_licenca_ui)
        abas.addTab(aba_licenca, "Licença e Termos de Uso")

        # ==============================================================
        # ABA 3: COMO CITAR (ABNT)
        # ==============================================================
        aba_citar = QWidget()
        layout_citar = QVBoxLayout(aba_citar)
        layout_citar.setContentsMargins(20, 20, 20, 20)  # Margens para o texto não colar no bordo

        texto_citar_ui = QTextEdit()
        texto_citar_ui.setReadOnly(True)
        texto_citar_ui.setStyleSheet("background-color: transparent; border: none; font-size: 10pt;")

        # Variáveis dinâmicas para o bloco de citação ABNT acompanhar o tema
        bg_bloco = "#3c3f41" if self.chk_modo_escuro.isChecked() else "#f4f4f4"
        cor_bloco = "#f0f0f0" if self.chk_modo_escuro.isChecked() else "#333333"

        conteudo_citar_html = (
            "<h3>📝 Como citar este software (ABNT)</h3>"
            "<p>Se utilizar o <b>Extrator de Hashes e Metadados (ERS-IC/SP-NIC)</b> em trabalhos acadêmicos, laudos periciais ou pesquisas, por favor, utilize a seguinte referência:</p>"
            "<br>"
            f"<div style='background-color: {bg_bloco}; border-left: 5px solid #005a9e; padding: 15px; font-family: Consolas, monospace; color: {cor_bloco}; line-height: 140%;'>"
            f"SILVA, Eduardo R. <b>Extrator de Hashes e Metadados (ERS-IC/SP-NIC)</b>. Versão {VERSAO_APP}. "
            f"São Paulo, SP: GitHub, 2026. Disponível em: &lt;<a href='{LINK_GITHUB}/releases' style='color: {cor_bloco}; text-decoration: none;'>{LINK_GITHUB}/releases</a>&gt;. "
            f"Acesso em: [Data de Acesso]."
            f"</div>"
            "<br><br>"
        )

        texto_citar_ui.setHtml(conteudo_citar_html)
        layout_citar.addWidget(texto_citar_ui)
        abas.addTab(aba_citar, "Como Citar")

        # ==============================================================
        # ABA 4: AGRADECIMENTOS
        # ==============================================================
        aba_agradecimentos = QWidget()
        layout_agradecimentos = QVBoxLayout(aba_agradecimentos)
        layout_agradecimentos.setContentsMargins(20, 20, 20, 20)

        texto_agradecimentos_ui = QTextEdit()
        texto_agradecimentos_ui.setReadOnly(True)
        texto_agradecimentos_ui.setStyleSheet("background-color: transparent; border: none; font-size: 10pt;")

        # Conteúdo em HTML padronizado com o restante do menu Sobre
        conteudo_agradecimentos_html = (
            "<h3>🤝 Agradecimentos</h3>"
            "<p>O desenvolvimento do <b>Extrator de Hashes e Metadados (ERS-IC/SP-NIC)</b> foi tornado possível graças ao "
            "apoio de colaboradores da área pericial e à robusta comunidade global de software livre.</p>"
            "<br>"
            "<b>Reconhecimentos Especiais:</b>"
            "<ul>"
            "<li><b>Apoio Institucional e Colegas:</b> Ao Diretor do Núcleo de Identificação Criminal Doutor Yuri Ojevan Presto e aos "
            "Peritos Criminais Doutor Marco Aurélio Santoro e Doutora Luana Maria Garcia de Lima que voluntariaram "
            "seu tempo realizando testes de estresse em lotes massivos, validação de metodologias e sugestões de interface e funcionalidades.</li>"
            "<li><b>Comunidade de Software Livre (Open-Source):</b> Aos criadores e mantenedores das ferramentas de base "
            "que compõem este ecossistema, com especial destaque para <i>Joachim Metz (projeto libewf e ewfacquire)</i>, "
            "<i>Phil Harvey (ExifTool)</i>, a equipe do <i>MediaInfo</i>, "
            "e os desenvolvedores do <i>PySide6/Qt</i>, <i>Pillow</i>, <i>pypdf</i>, <i>LnkParse3</i> e <i>pefile</i>. "
            "Um agradecimento adicional à comunidade da <i>Alpine Security</i> por disponibilizar os binários compilados do ewf-tools para Windows.</li>"
            "</ul>"
            "<p>Este projeto reforça o compromisso da comunidade pericial com a transparência e auditabilidade das "
            "ferramentas de extração de prova digital.</p>"
        )

        texto_agradecimentos_ui.setHtml(conteudo_agradecimentos_html)
        layout_agradecimentos.addWidget(texto_agradecimentos_ui)
        abas.addTab(aba_agradecimentos, "Agradecimentos")

        # --- RODAPÉ ---
        layout_botoes = QHBoxLayout()
        btn_audit = QPushButton("📂 Baixar Código Fonte para Auditoria (.py)")
        btn_audit.setMinimumHeight(35)
        cor_btn_audit = "#66b2ff" if is_dark else "#005a9e"
        btn_audit.setStyleSheet(f"font-weight: bold; color: {cor_btn_audit};")
        btn_audit.clicked.connect(self.exportar_codigo_fonte)

        # Botão para fechar
        btn_fechar = QPushButton("Fechar")
        btn_fechar.setMinimumHeight(35)
        btn_fechar.clicked.connect(dialog.accept)

        layout_botoes.addWidget(btn_audit)
        layout_botoes.addStretch()
        layout_botoes.addWidget(btn_fechar)
        layout_principal.addLayout(layout_botoes)

        dialog.setLayout(layout_principal)
        dialog.exec()

    def abrir_manual_online(self):
        import webbrowser
        webbrowser.open("https://github.com/eduardo-rsilva/extrator_hashes_metadados/blob/master/MANUAL.md")

    def mostrar_formatos(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Formatos Suportados para Metadados Básicos")
        dialog.resize(600, 550)

        layout = QVBoxLayout()

        texto_formatos = QTextEdit()
        texto_formatos.setReadOnly(True)
        if self.chk_modo_escuro.isChecked():
            texto_formatos.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; font-size: 10pt; border: none;")
        else:
            texto_formatos.setStyleSheet("background-color: #ffffff; color: #111111; font-size: 10pt; border: none;")

        conteudo_html = f"""
            <h2>Formatos Suportados para Extração de Metadados Básicos</h2>
            <p>A ferramenta utiliza o <b>ExifTool</b> e bibliotecas nativas para analisar os seguintes arquivos:</p>

            <h3>📷 Imagens</h3>
            <p>{', '.join([ext.upper() for ext in FORMATOS_IMAGEM])}</p>
            
            <h3>🎬 Vídeos</h3>
            <p>{', '.join([ext.upper() for ext in FORMATOS_VIDEO])}</p>
            
            <h3>🎵 Áudios</h3>
            <p>{', '.join([ext.upper() for ext in FORMATOS_AUDIO])}</p>
            
            <h3>📄 Documentos e Outros (Análise Nativa/Heurística)</h3>
            <p>{', '.join([ext.upper() for ext in FORMATOS_GERAIS])}</p>
        """

        texto_formatos.setHtml(conteudo_html)
        layout.addWidget(texto_formatos)

        btn_fechar = QPushButton("Fechar")
        btn_fechar.clicked.connect(dialog.accept)
        layout.addWidget(btn_fechar)

        dialog.setLayout(layout)
        dialog.exec()

    def travar_interface(self):
        self.processando = True

        # Trava as duas novas caixas superiores inteiras de uma vez
        # (Isso desativa automaticamente: Arquivos, Diretório, RAW, Subdirs, Modo Escuro, Sobre, Formatos, etc.)
        self.grupo_wb.setEnabled(False)
        self.grupo_topo.setEnabled(False)
        self.grupo_controles.setEnabled(False)

        # Trava os botões do rodapé
        self.btn_limpar.setEnabled(False)
        self.btn_copiar.setEnabled(False)
        self.btn_salvar.setEnabled(False)

        # Trava a área de cadeia de custódia e o drag & drop global
        self.setAcceptDrops(False)
        self.texto_referencia.setEnabled(False)
        self.btn_limpar_custodia.setEnabled(False)

    def destravar_interface(self):
        self.processando = False

        # Destrava as duas novas caixas superiores inteiras de uma vez
        self.grupo_wb.setEnabled(True)
        self.grupo_topo.setEnabled(True)
        self.grupo_controles.setEnabled(True)

        # Destrava os botões do rodapé
        self.btn_limpar.setEnabled(True)
        self.btn_copiar.setEnabled(True)
        self.btn_salvar.setEnabled(True)

        # Destrava a área de cadeia de custódia e o drag & drop global
        self.setAcceptDrops(True)
        self.texto_referencia.setEnabled(True)
        self.btn_limpar_custodia.setEnabled(True)


    # --- EXTRAÇÃO AVANÇADA DE METADADOS ---
    def obter_metadados_avancados(self, caminho_arquivo, extrair_raw=False):
        """Distribui o arquivo para o extrator correto baseado na extensão."""
        metadados_extras = []
        raw_dump = []
        extensao = caminho_arquivo.lower().split('.')[-1]

        # Flag para controlar o ExifTool Universal no final da função
        exiftool_executado = False

        # --- DETECÇÃO DE ADS (Roda para todos os arquivos) ---
        streams = detectar_ads_windows(caminho_arquivo)
        if streams:
            metadados_extras.extend(streams)
        # -----------------------------------------------------

        # --- ANÁLISE HEURÍSTICA DE NOME DE ARQUIVO (LAVAGEM DE METADADOS) ---
        nome_base = os.path.basename(caminho_arquivo).lower()
        plataforma_detectada = None
        padrao_encontrado = None

        if "whatsapp" in nome_base:
            plataforma_detectada = "WhatsApp"
            padrao_encontrado = "whatsapp"
        elif nome_base.startswith("aud-") and extensao in FORMATOS_AUDIO:
            plataforma_detectada = "WhatsApp"
            padrao_encontrado = "aud-"
        elif nome_base.startswith("ptt-") and extensao in FORMATOS_AUDIO:
            plataforma_detectada = "WhatsApp"
            padrao_encontrado = "ptt-"
        elif "telegram" in nome_base:
            plataforma_detectada = "Telegram"
            padrao_encontrado = "telegram"
        elif "instagram" in nome_base:
            plataforma_detectada = "Instagram"
            padrao_encontrado = "instagram"
        elif "fb_img" in nome_base:
            plataforma_detectada = "Facebook/Messenger"
            padrao_encontrado = "fb_img"
        elif "received_" in nome_base:
            plataforma_detectada = "Facebook/Messenger"
            padrao_encontrado = "received_"
        elif "twimg" in nome_base:
            plataforma_detectada = "Twitter/X"
            padrao_encontrado = "twimg"
        elif "twitter" in nome_base:
            plataforma_detectada = "Twitter/X"
            padrao_encontrado = "twitter"

        if plataforma_detectada:
            metadados_extras.append(
                f"⚠️ ALERTA: Padrão de nomenclatura do {plataforma_detectada} detectado no título: '{padrao_encontrado}'")
            metadados_extras.append(
                f"   ↳ Nota: A plataforma {plataforma_detectada} realiza 'Metadata Stripping' (Lavagem de Metadados).")
            metadados_extras.append(
                f"   ↳ Dados originais como Câmera, GPS e Data de Criação interna são destruídos em envios via {plataforma_detectada}.")
        # --------------------------------------------------------------------

        # 1. IMAGENS (Todos os formatos visuais/imagem suportados pelo ExifTool + fallback do Pillow)
        if extensao in FORMATOS_IMAGEM:
            caminho_exiftool = obter_caminho_exiftool()
            usou_exiftool = False

            max_wait_time = 15

            # --- TENTATIVA 1: ExifTool (Forense e Completo) ---
            if caminho_exiftool:
                try:
                    cmd = [caminho_exiftool, "-charset", "filename=latin", "-charset", "utf8", "-j", "-G", "-a", "-ee", "-api", "largefilesupport=1", "-c", "%+.6f", caminho_arquivo]

                    processo = subprocess.run(
                        cmd,
                        capture_output=True,
                        encoding='utf-8',
                        errors='replace',
                        timeout=max_wait_time,
                        creationflags=0x08000000 if os.name == 'nt' else 0
                    )

                    if processo.returncode == 0:
                        dados_json = json.loads(processo.stdout)
                        if dados_json:
                            meta = dados_json[0]
                            exiftool_executado = True
                            if extrair_raw:
                                raw_dump.append("\n=== EXIFTOOL (RAW) ===")
                                for key_raw, val_raw in meta.items():
                                    raw_dump.append(f"{key_raw}: {val_raw}")
                            usou_exiftool = True

                            largura = meta.get('File:ImageWidth') or meta.get('Composite:ImageWidth') or meta.get(
                                'EXIF:ExifImageWidth')
                            altura = meta.get('File:ImageHeight') or meta.get('Composite:ImageHeight') or meta.get(
                                'EXIF:ExifImageHeight')
                            if largura and altura:
                                metadados_extras.append(f"Resolução: {largura}x{altura} pixels")

                            formato = meta.get('File:FileType')
                            if formato:
                                metadados_extras.append(f"Formato: {formato}")

                            dpi_x = meta.get('EXIF:XResolution') or meta.get('IFD0:XResolution')
                            dpi_y = meta.get('EXIF:YResolution') or meta.get('IFD0:YResolution')
                            if dpi_x and dpi_y:
                                metadados_extras.append(f"DPI: {int(dpi_x)}x{int(dpi_y)}")
                            else:
                                metadados_extras.append("DPI: Não especificado (Padrão: 96x96)")

                            marca = meta.get('IFD0:Make') or meta.get('EXIF:Make')
                            modelo = meta.get('IFD0:Model') or meta.get('EXIF:Model')
                            if modelo:
                                disp = f"{marca} {modelo}" if marca else modelo
                                metadados_extras.append(f"📷 Dispositivo (EXIF): {disp.strip()}")

                            data_captura = meta.get('EXIF:DateTimeOriginal') or meta.get('IFD0:ModifyDate')
                            if data_captura:
                                fuso = meta.get('EXIF:OffsetTimeOriginal') or meta.get('EXIF:OffsetTime')
                                if fuso:
                                    metadados_extras.append(
                                        f"⏱️ Data de Captura (EXIF): {data_captura} (Fuso: {fuso})")
                                else:
                                    metadados_extras.append(f"⏱️ Data de Captura (EXIF): {data_captura}")

                            software = meta.get('IFD0:Software') or meta.get('EXIF:Software') or meta.get(
                                'XMP:CreatorTool')
                            if software:
                                metadados_extras.append(f"💻 Software/Editor: {software}")

                            gps_lat = meta.get('Composite:GPSLatitude')
                            gps_lon = meta.get('Composite:GPSLongitude')
                            if gps_lat and gps_lon:
                                try:
                                    lat_float = float(gps_lat)
                                    lon_float = float(gps_lon)
                                    link_maps = f"https://www.google.com/maps/search/?api=1&query={lat_float:.6f},{lon_float:.6f}"
                                    metadados_extras.append(
                                        f"📍 GPS (Latitude, Longitude): {lat_float:.6f}, {lon_float:.6f}")
                                    metadados_extras.append(f"   ↳ Visualizar no Mapa: {link_maps}")
                                except ValueError:
                                    metadados_extras.append(f"📍 GPS (Bruto): {gps_lat}, {gps_lon}")

                            orientacao = meta.get('EXIF:Orientation') or meta.get('IFD0:Orientation')
                            if orientacao:
                                orientacoes = {
                                    '1': 'Normal', '2': 'Espelhado horizontal', '3': 'Rotacionado 180°',
                                    '4': 'Espelhado vertical', '5': 'Rotacionado 90° CCW + Espelhado horizontal',
                                    '6': 'Rotacionado 90° CW', '7': 'Rotacionado 90° CW + Espelhado horizontal',
                                    '8': 'Rotacionado 90° CCW'
                                }
                                desc = orientacoes.get(str(orientacao), f'Código {orientacao}')
                                metadados_extras.append(f"🔄 Orientação (EXIF): {orientacao} — {desc}")


                except subprocess.TimeoutExpired:
                    nome_arq = os.path.basename(caminho_arquivo)
                    metadados_extras.append(f"⚠️ EXIFTOOL ABORTADO: Tempo limite de {max_wait_time}s excedido (Prevenção de travamento).")
                    metadados_extras.append("   ↳ O arquivo é muito grande ou complexo para processamento em lote.")
                    metadados_extras.append("   ↳ ORIENTAÇÃO PERICIAL: Realize a extração manualmente. Abra o CMD/PowerShell na pasta do arquivo e execute:")
                    metadados_extras.append(f"   ↳ Comando: exiftool -j -G \"{nome_arq}\" > dump_metadados.json")
                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao ler metadados da imagem com ExifTool: {e}")

            else:
                pasta_esperada = "exiftool-13.59_64" if sys.maxsize > 2 ** 32 else "exiftool-13.59_32"
                metadados_extras.append(
                    f"⚠️ ExifTool ausente: O programa exige a pasta '{pasta_esperada}' no diretório do executável para extrair GPS e datas reais.")

            # --- TENTATIVA 2: Fallback ou Complementar para o Pillow ---
            if not usou_exiftool or extrair_raw:
                if HAS_PIL:
                    try:
                        with Image.open(caminho_arquivo) as img:
                            if not usou_exiftool:
                                metadados_extras.append(f"Resolução (Pillow): {img.width}x{img.height} pixels")
                                metadados_extras.append(f"Formato (Pillow): {img.format}")
                                metadados_extras.append(f"Modo de Cor: {img.mode}")

                            if extrair_raw:
                                raw_dump.append("\n=== PILLOW / PIL (RAW) ===")
                                for k, v in img.info.items():
                                    if isinstance(v, (str, int, float, tuple)):
                                        raw_dump.append(f"{k}: {v}")
                                    else:
                                        raw_dump.append(f"{k}: [Dados Binários / Estrutura Complexa]")
                    except Exception as e:
                        if not usou_exiftool:
                            metadados_extras.append(f"⚠️ Erro ao ler metadados com Pillow (possivelmente não é um arquivo de imagem): {e}")
                else:
                    if not usou_exiftool:
                        metadados_extras.append(
                            "⚠️ Biblioteca Pillow (PIL) ausente: Não foi possível realizar a leitura secundária da imagem.")

        # 2. VÍDEOS (Busca Abrangente Universal)
        elif extensao in FORMATOS_VIDEO:

            # --- PARTE 1: MediaInfo (Dados Estruturais e FPS Exato) ---
            if HAS_PYMEDIAINFO:
                try:
                    media_info = MediaInfo.parse(caminho_arquivo)
                    if extrair_raw:
                        raw_dump.append("\n=== MEDIAINFO (RAW) ===")
                        for track_raw in media_info.tracks:
                            raw_dump.append(f"--- Trilha: {track_raw.track_type} ---")
                            for key_raw, val_raw in track_raw.to_data().items():
                                if val_raw is not None:
                                    raw_dump.append(f"{key_raw}: {val_raw}")
                    video_track = next((t for t in media_info.tracks if t.track_type == "Video"), None)

                    if not video_track:
                        metadados_extras.append("⚠️ MediaInfo não encontrou trilha de vídeo válida neste arquivo.")

                    if video_track:
                        if video_track.width and video_track.height:
                            metadados_extras.append(
                                f"Resolução de exibição: {video_track.width}x{video_track.height} pixels")

                        dar = getattr(video_track, "display_aspect_ratio", None) or getattr(video_track,
                                                                                            "other_display_aspect_ratio",
                                                                                            None)
                        par = getattr(video_track, "pixel_aspect_ratio", None) or getattr(video_track,
                                                                                          "other_pixel_aspect_ratio",
                                                                                          None)

                        if isinstance(dar, list):
                            dar = dar[0] if dar else None
                        if isinstance(par, list):
                            par = par[0] if par else None

                        if dar:
                            dar_str = str(dar).strip()
                            if ":" not in dar_str:
                                try:
                                    dar_float = float(dar_str)
                                    if 1.77 <= dar_float <= 1.78:
                                        dar_str = f"16:9 (Widescreen) — Valor registrado: {dar_str}"
                                    elif 1.33 <= dar_float <= 1.34:
                                        dar_str = f"4:3 (Tela clássica) — Valor registrado: {dar_str}"
                                    elif 0.56 <= dar_float <= 0.57:
                                        dar_str = f"9:16 (Vertical/Smartphone) — Valor registrado: {dar_str}"
                                    elif dar_float == 0.75:
                                        dar_str = f"3:4 (Vertical clássico) — Valor registrado: {dar_str}"
                                    elif dar_float == 1.0:
                                        dar_str = f"1:1 (Quadrado) — Valor registrado: {dar_str}"
                                    elif 2.33 <= dar_float <= 2.40:
                                        dar_str = f"2.35:1 / 21:9 (Formato Cinema) — Valor registrado: {dar_str}"
                                except ValueError:
                                    pass
                            metadados_extras.append(f"Razão de Proporção (Display Aspect Ratio): {dar_str}")

                        if par and str(par).strip() not in ("1", "1.0", "1.00", "1.000"):
                            metadados_extras.append(
                                f"Razão do Pixel (PAR): {par} (Vídeo com pixels anamórficos/esticados)")

                        w_stored = getattr(video_track, 'stored_width', video_track.width) or video_track.width
                        h_stored = getattr(video_track, 'stored_height', video_track.height) or video_track.height

                        if str(w_stored) != str(video_track.width) or str(h_stored) != str(video_track.height):
                            metadados_extras.append(f"Resolução codificada real: {w_stored}x{h_stored} pixels")
                            metadados_extras.append(
                                "  ↳ Nota técnica: alguns decodificadores podem usar alinhamento interno adicional além do tamanho codificado; esse valor depende da ferramenta e não é uma propriedade universal do arquivo.")

                        fps = video_track.frame_rate
                        if fps:
                            metadados_extras.append(f"FPS Média/Base: {fps}")

                        if video_track.frame_rate_nominal:
                            metadados_extras.append(f"FPS Nominal: {video_track.frame_rate_nominal}")
                        if video_track.minimum_frame_rate:
                            metadados_extras.append(f"FPS Mínimo: {video_track.minimum_frame_rate}")
                        if video_track.maximum_frame_rate:
                            metadados_extras.append(f"FPS Máximo: {video_track.maximum_frame_rate}")

                        if video_track.frame_rate_nominal or fps:
                            self.video_teve_fps_geral = True
                        if video_track.minimum_frame_rate or video_track.maximum_frame_rate:
                            self.video_teve_fps_min_max = True

                        total_frames = video_track.frame_count
                        if total_frames:
                            metadados_extras.append(f"Total de Frames: {total_frames}")

                        duracao_ms = video_track.duration
                        if duracao_ms:
                            duracao_segundos = float(duracao_ms) / 1000
                            mins, secs = divmod(duracao_segundos, 60)
                            horas, mins = divmod(mins, 60)
                            milisegundos = int(round((duracao_segundos - int(duracao_segundos)) * 1000))
                            metadados_extras.append(
                                f"Duração Extraída (MediaInfo): {int(horas):02d}h{int(mins):02d}min{int(secs):02d},{milisegundos:03d}s")

                            if total_frames:
                                fps_medio_real = int(total_frames) / duracao_segundos
                                metadados_extras.append(f"FPS Calculado (Frames/Duração): {fps_medio_real:.3f}")

                        if video_track.format:
                            metadados_extras.append(f"Formato do Codec de Vídeo: {video_track.format}")
                        if video_track.color_space:
                            metadados_extras.append(f"Espaço de Cor: {video_track.color_space}")
                        if video_track.chroma_subsampling:
                            metadados_extras.append(f"Subamostragem Cromática: {video_track.chroma_subsampling}")
                        if video_track.scan_type:
                            metadados_extras.append(f"Tipo de Varredura: {video_track.scan_type}")
                        if video_track.track_id:
                            metadados_extras.append(f"ID da Trilha de Vídeo: {video_track.track_id}")

                    general_track = next((t for t in media_info.tracks if t.track_type == "General"), None)
                    if general_track:
                        if general_track.format:
                            metadados_extras.append(f"Formato do Container: {general_track.format}")
                        if general_track.overall_bit_rate:
                            metadados_extras.append(f"Taxa de Bits Global: {general_track.overall_bit_rate}bps")
                        if general_track.encoded_date:
                            metadados_extras.append(
                                f"Data de Codificação (MediaInfo): {general_track.encoded_date}")
                        if general_track.recorded_date:
                            metadados_extras.append(f"Data de Gravação (MediaInfo): {general_track.recorded_date}")

                        for attr, valor in general_track.__dict__.items():
                            if valor and isinstance(valor, str) and (
                                    attr.startswith('com_') or attr.startswith('com.') or
                                    'manufacturer' in attr.lower() or 'model' in attr.lower() or
                                    'product' in attr.lower() or 'vendor' in attr.lower() or
                                    'brand' in attr.lower() or 'serial' in attr.lower() or 'sn' in attr.lower()
                            ):
                                nome_limpo = attr.replace('_', '.', 1) if attr.startswith('com_') else attr
                                if attr.startswith('com_'):
                                    partes = attr.split('_', 2)
                                    if len(partes) >= 3:
                                        sub = partes[2].replace('_', '.', 1) if '_' in partes[2] else partes[2]
                                        nome_limpo = f"{partes[0]}.{partes[1]}.{sub}"
                                metadados_extras.append(f"📱 Dispositivo (MediaInfo): {nome_limpo} = {valor}")

                    audio_track = next((t for t in media_info.tracks if t.track_type == "Audio"), None)
                    if audio_track:
                        if audio_track.format:
                            metadados_extras.append(f"Codec de Áudio (MediaInfo): {audio_track.format}")
                        if audio_track.channels:
                            canais = "Mono" if int(audio_track.channels) == 1 else "Estéreo" if int(
                                audio_track.channels) == 2 else f"{audio_track.channels} canais"
                            metadados_extras.append(f"Canais de Áudio: {canais}")
                        if audio_track.sampling_rate:
                            metadados_extras.append(f"Sample Rate: {audio_track.sampling_rate}Hz")
                        if audio_track.bit_rate:
                            metadados_extras.append(f"Bitrate de Áudio: {audio_track.bit_rate}bps")
                        if audio_track.track_id:
                            metadados_extras.append(f"ID da Trilha de Áudio: {audio_track.track_id}")

                        total_trilhas = len(media_info.tracks)
                        if total_trilhas > 3:
                            metadados_extras.append(
                                f"⚠️ Múltiplas Trilhas Detectadas: {total_trilhas} trilhas no total(possível gravação com múltiplas fontes)")
                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao processar estrutura do vídeo com MediaInfo: {e}")

            # --- PARTE 1.5: OpenCV Fallback ou Complementar ---
            if not HAS_PYMEDIAINFO or extrair_raw:
                if HAS_CV2:
                    try:
                        cap = cv2.VideoCapture(caminho_arquivo)
                        if cap.isOpened():
                            largura = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
                            altura = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                            fps = cap.get(cv2.CAP_PROP_FPS)
                            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

                            if extrair_raw:
                                raw_dump.append("\n=== OPENCV (RAW) ===")
                                raw_dump.append(f"CAP_PROP_FRAME_WIDTH: {largura}")
                                raw_dump.append(f"CAP_PROP_FRAME_HEIGHT: {altura}")
                                raw_dump.append(f"CAP_PROP_FPS: {fps}")
                                raw_dump.append(f"CAP_PROP_FRAME_COUNT: {total_frames}")
                                raw_dump.append(f"CAP_PROP_FORMAT: {cap.get(cv2.CAP_PROP_FORMAT)}")

                            if not HAS_PYMEDIAINFO:
                                if largura > 0 and altura > 0:
                                    metadados_extras.append(f"Resolução do Vídeo: {largura}x{altura}")
                                    divisor = math.gcd(largura, altura)
                                    razao_w = largura // divisor
                                    razao_h = altura // divisor
                                    metadados_extras.append(f"Razão de Proporção (Calculada): {razao_w}:{razao_h}")

                                if fps > 0:
                                    metadados_extras.append(f"FPS (Aproximado/CV2): {fps:.3f}")
                                    if total_frames > 0:
                                        metadados_extras.append(f"Total de Frames: {total_frames}")
                                        duracao = total_frames / fps
                                        mins, secs = divmod(duracao, 60)
                                        horas, mins = divmod(mins, 60)
                                        milisegundos = int(round((duracao - int(duracao)) * 1000))
                                        metadados_extras.append(
                                            f"Duração Calculada (via FPS): {int(horas):02d}h{int(mins):02d}min{int(secs):02d},{milisegundos:03d}s")
                            cap.release()
                        else:
                            if not HAS_PYMEDIAINFO:
                                metadados_extras.append("⚠️ OpenCV falhou ao abrir o vídeo.")
                    except Exception as e:
                        if not HAS_PYMEDIAINFO:
                            metadados_extras.append(f"⚠️ Erro ao processar estrutura do vídeo com OpenCV: {e}")
                else:
                    if not HAS_PYMEDIAINFO:
                        metadados_extras.append(
                            "⚠️ Bibliotecas MediaInfo e OpenCV ausentes: Impossível extrair resolução e duração estimadas.")

            # --- PARTE 2: ExifTool (Metadados Forenses de Vídeo) ---
            caminho_exiftool = obter_caminho_exiftool()
            if caminho_exiftool:
                try:
                    cmd = [caminho_exiftool, "-charset", "filename=latin", "-charset", "utf8", "-j", "-G", "-a", "-ee", "-api", "largefilesupport=1", "-c", "%+.6f", caminho_arquivo]
                    processo = subprocess.run(
                        cmd, capture_output=True, encoding='utf-8', errors='replace', timeout=20,
                        creationflags=0x08000000 if os.name == 'nt' else 0
                    )

                    if processo.returncode == 0:
                        dados_json = json.loads(processo.stdout)
                        if dados_json:
                            meta = dados_json[0]
                            exiftool_executado = True
                            if extrair_raw:
                                raw_dump.append("\n=== EXIFTOOL (RAW) ===")
                                for key_raw, val_raw in meta.items():
                                    raw_dump.append(f"{key_raw}: {val_raw}")
                            exif_video_telemetria = False

                            data_criacao = meta.get('QuickTime:CreateDate') or meta.get(
                                'QuickTime:ContentCreateDate')
                            data_modificacao = meta.get('QuickTime:ModifyDate')
                            if data_criacao:
                                fuso = meta.get('QuickTime:LocationInformation') or meta.get('XMP:Timezone')
                                if fuso:
                                    metadados_extras.append(
                                        f"⏱️ Data de Criação do Vídeo: {data_criacao}(Fuso: {fuso})")
                                else:
                                    metadados_extras.append(f"⏱️ Data de Criação do Vídeo: {data_criacao}")
                                exif_video_telemetria = True
                            if data_modificacao and data_modificacao != data_criacao:
                                metadados_extras.append(f"⏱️ Data de Modificação do Vídeo: {data_modificacao}")
                                exif_video_telemetria = True

                            make = meta.get('QuickTime:Make')
                            model = meta.get('QuickTime:Model')
                            if model:
                                disp = f"{make} {model}" if make else model
                                metadados_extras.append(f"📱 Dispositivo (ExifTool):{disp.strip()}")
                                exif_video_telemetria = True

                            software = meta.get('QuickTime:Software') or meta.get('XMP:CreatorTool')
                            if software:
                                metadados_extras.append(f"💻 Software/Editor: {software}")
                                exif_video_telemetria = True

                            video_codec = meta.get('QuickTime:VideoCodec') or meta.get('RIFF:VideoCodec')
                            audio_codec = meta.get('QuickTime:AudioCodec') or meta.get('RIFF:AudioCodec')
                            if video_codec:
                                metadados_extras.append(f"Codec de Vídeo (ExifTool): {video_codec}")
                                exif_video_telemetria = True
                            if audio_codec:
                                metadados_extras.append(f"Codec de Áudio (ExifTool): {audio_codec}")
                                exif_video_telemetria = True

                            avg_bitrate = meta.get('QuickTime:AvgBitrate') or meta.get('RIFF:AvgBitRate')
                            if avg_bitrate:
                                metadados_extras.append(f"Taxa de Bits Média (ExifTool): {avg_bitrate}")
                                exif_video_telemetria = True

                            rotation = (meta.get('Composite:Rotation') or meta.get(
                                'QuickTime:Rotation') or meta.get('Track1:Rotation') or meta.get('RIFF:Rotation'))
                            if rotation:
                                metadados_extras.append(f"🔄 Rotação do Vídeo: {rotation}°")
                                exif_video_telemetria = True

                            matrix = meta.get('QuickTime:MatrixStructure') or meta.get('Track1:MatrixStructure')
                            if matrix:
                                try:
                                    if isinstance(matrix, str):
                                        valores_matriz = [float(v) for v in matrix.replace(',', ' ').split() if
                                                          v.strip()]
                                    elif isinstance(matrix, list):
                                        valores_matriz = [float(v) for v in matrix]
                                    else:
                                        valores_matriz = []

                                    if len(valores_matriz) >= 5:
                                        escala_x = valores_matriz[0]
                                        escala_y = valores_matriz[4]
                                        espelhamentos = []
                                        if escala_x < 0: espelhamentos.append("Horizontal")
                                        if escala_y < 0: espelhamentos.append("Vertical")

                                        if espelhamentos:
                                            tipo_espelhamento = " + ".join(espelhamentos)
                                            metadados_extras.append(
                                                f"🪞 Espelhamento Detectado (Vídeo): Sim ({tipo_espelhamento})")
                                        else:
                                            metadados_extras.append(
                                                "🪞 Espelhamento Detectado (Vídeo): Não (Orientação nativa/original)")
                                        exif_video_telemetria = True
                                except Exception:
                                    pass

                            gps_lat = meta.get('Composite:GPSLatitude')
                            gps_lon = meta.get('Composite:GPSLongitude')
                            if gps_lat and gps_lon:
                                try:
                                    lat_float = float(gps_lat)
                                    lon_float = float(gps_lon)
                                    link_maps = f"https://www.google.com/maps/search/?api=1&query={lat_float:.6f},{lon_float:.6f}"
                                    metadados_extras.append(
                                        f"📍 GPS (Latitude, Longitude): {lat_float: .6f}, {lon_float: .6f}")
                                    metadados_extras.append(f" ↳ Visualizar no Mapa: {link_maps}")
                                    exif_video_telemetria = True
                                except ValueError:
                                    metadados_extras.append(f"📍 GPS (Bruto): {gps_lat}, {gps_lon}")

                            gps_alt = meta.get('QuickTime:GPSAltitude')
                            if gps_alt:
                                metadados_extras.append(f"📏 Altitude GPS: {gps_alt} m")
                                exif_video_telemetria = True

                            gps_speed = meta.get('QuickTime:GPSSpeed')
                            if gps_speed:
                                metadados_extras.append(f"🏎️ Velocidade GPS: {gps_speed}")
                                exif_video_telemetria = True

                            content_id = meta.get('QuickTime:ContentIdentifier')
                            if content_id:
                                metadados_extras.append(f"🆔 Content Identifier (UUID): {content_id}")
                                exif_video_telemetria = True

                            serial = (meta.get('QuickTime:CameraSerialNumber') or meta.get(
                                'XMP:CameraSerialNumber') or meta.get('QuickTime:UniqueID') or meta.get(
                                'DJI:DeviceSerialNumber'))
                            if serial:
                                metadados_extras.append(f"🔢 Número de Série do Dispositivo: {serial}")
                                exif_video_telemetria = True

                            if not data_criacao and not model:
                                metadados_extras.append(
                                    "⚠️ Metadados de autoria e data ausentes — possível remoção intencional de metadados(metadata stripping).")
                                exif_video_telemetria = True

                            metadados_str = ' '.join(str(v).lower() for v in meta.values() if v)
                            dvr_keywords = ['hikvision', 'dahua', 'intelbras', 'standalone', 'dvr', 'nvr']
                            dvr_detectado = [kw for kw in dvr_keywords if kw in metadados_str]
                            if dvr_detectado:
                                metadados_extras.append(
                                    f"🎥 Indício de Câmera de Vigilância/DVR detectado: {', '.join(dvr_detectado)}")
                                exif_video_telemetria = True

                            for chave, valor in meta.items():
                                chave_lower = chave.lower()
                                if 'drone' in chave_lower or 'gimbal' in chave_lower:
                                    metadados_extras.append(
                                        f"🚁 Telemetria de Drone: {chave.split(':')[-1]} = {valor}")
                                    exif_video_telemetria = True

                            comment = meta.get('QuickTime:Comment') or meta.get('RIFF:Comment')
                            if comment:
                                metadados_extras.append(f"Comentário do Vídeo: {comment}")
                                exif_video_telemetria = True

                            description = meta.get('QuickTime:Description')
                            if description:
                                metadados_extras.append(f"Descrição do Vídeo: {description}")
                                exif_video_telemetria = True

                            producer = meta.get('QuickTime:Producer') or meta.get('XMP:Producer')
                            if producer:
                                metadados_extras.append(f"Produtor do Vídeo: {producer}")
                                exif_video_telemetria = True

                            vendor = meta.get('QuickTime:Vendor')
                            if vendor:
                                metadados_extras.append(f"Fabricante (Vendor): {vendor}")
                                exif_video_telemetria = True

                            riff_software = meta.get('RIFF:Software')
                            if riff_software and not software:
                                metadados_extras.append(f"Software do Container (RIFF): {riff_software}")
                                exif_video_telemetria = True

                            if not exif_video_telemetria:
                                metadados_extras.append(
                                    "ℹ️ ExifTool analisou o vídeo, mas não encontrou metadados forenses adicionais(GPS, dispositivo, data de criação).")


                except subprocess.TimeoutExpired:
                    nome_arq = os.path.basename(caminho_arquivo)
                    metadados_extras.append("⚠️ EXIFTOOL ABORTADO: Tempo limite de 20s excedido (Prevenção de travamento).")
                    metadados_extras.append("   ↳ O vídeo é muito extenso para processamento em lote.")
                    metadados_extras.append("   ↳ ORIENTAÇÃO PERICIAL: Realize a extração manualmente. Abra o CMD/PowerShell na pasta do arquivo e execute:")
                    metadados_extras.append(f"   ↳ Comando: exiftool -j -G \"{nome_arq}\" > dump_metadados.json")
                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao ler metadados forenses do vídeo com ExifTool: {e}")
            else:
                pasta_esperada = "exiftool-13.59_64" if sys.maxsize > 2 ** 32 else "exiftool-13.59_32"
                metadados_extras.append(
                    f"⚠️ ExifTool ausente: Não foi possível extrair GPS, dispositivo e data de criação do vídeo.Pasta esperada: '{pasta_esperada}'.")

        # 3. PDFs
        elif extensao in FORMATOS_PDF:
            if HAS_PYPDF:
                try:
                    reader = PdfReader(caminho_arquivo)
                    metadados_extras.append(f"Total de Páginas: {len(reader.pages)}")
                    meta = reader.metadata

                    if extrair_raw and meta:
                        raw_dump.append("\n=== PYPDF (RAW) ===")
                        for key_raw, val_raw in meta.items():
                            raw_dump.append(f"{key_raw}: {val_raw}")

                    extraiu_algo = False
                    if meta:
                        if meta.title:
                            metadados_extras.append(f"Título: {meta.title}")
                            extraiu_algo = True
                        if meta.author:
                            metadados_extras.append(f"Autor: {meta.author}")
                            extraiu_algo = True
                        if meta.creator:
                            metadados_extras.append(f"Criador/Software: {meta.creator}")
                            extraiu_algo = True

                    if not extraiu_algo:
                        metadados_extras.append("ℹ️ Metadados de Autoria ou Título não localizados neste PDF.")

                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao tentar processar PDF com pypdf: {e}")
            else:
                metadados_extras.append(
                    "⚠️ Biblioteca pypdf ausente: Não foi possível extrair os metadados do PDF.")

        # 4. PACOTE OFFICE (docx, xlsx, pptx)
        elif extensao in FORMATOS_OFFICE_XML:
            try:
                with zipfile.ZipFile(caminho_arquivo, 'r') as z:
                    if 'docProps/core.xml' in z.namelist():
                        conteudo_xml = z.read('docProps/core.xml')
                        root = ET.fromstring(conteudo_xml)
                        extraiu_algo = False

                        ns = {
                            'dc': 'http://purl.org/dc/elements/1.1/',
                            'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties'
                        }

                        criador = root.find('.//dc:creator', ns)
                        modificador = root.find('.//cp:lastModifiedBy', ns)
                        titulo = root.find('.//dc:title', ns)

                        if criador is not None and criador.text:
                            metadados_extras.append(f"Autor (Office): {criador.text}")
                            extraiu_algo = True
                        if modificador is not None and modificador.text:
                            metadados_extras.append(f"Último a Modificar (Office): {modificador.text}")
                            extraiu_algo = True
                        if titulo is not None and titulo.text:
                            metadados_extras.append(f"Título Interno (Office): {titulo.text}")
                            extraiu_algo = True

                        if extrair_raw:
                            raw_dump.append("\n=== OFFICE CORE.XML (RAW) ===")
                            for elem in root.iter():
                                tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                                if elem.text and elem.text.strip():
                                    raw_dump.append(f"{tag}: {elem.text.strip()}")

                        if not extraiu_algo:
                            metadados_extras.append(
                                "ℹ️ Metadados de autoria (Office XML) não localizados ou removidos.")
                    else:
                        metadados_extras.append(
                            "⚠️ Arquivo Office inválido: A estrutura XML esperada (docProps/core.xml) não foi encontrada.")

            except zipfile.BadZipFile:
                metadados_extras.append(
                    "⚠️ Erro ao ler Office: O arquivo está corrompido ou não é um ZIP válido (arquivos .docx/.xlsx/.pptx são ZIPs internamente).")
            except ET.ParseError:
                metadados_extras.append("⚠️ Erro ao ler Office: O XML de metadados está malformado ou corrompido.")
            except Exception as e:
                metadados_extras.append(f"⚠️ Erro ao tentar processar metadados XML do Office: {e}")

        # 5. PACOTE OFFICE LEGADO (doc, xls, ppt)
        elif extensao in FORMATOS_OFFICE_LEGADO:
            if HAS_OLEFILE:
                try:
                    if olefile.isOleFile(caminho_arquivo):
                        with olefile.OleFileIO(caminho_arquivo) as ole:
                            meta = ole.get_metadata()
                            extraiu_algo = False

                            def decodificar(valor):
                                if isinstance(valor, bytes):
                                    return valor.decode('utf-8', errors='ignore')
                                return str(valor) if valor else None

                            autor = decodificar(getattr(meta, 'author', None))
                            modificador = decodificar(getattr(meta, 'last_saved_by', None))
                            titulo = decodificar(getattr(meta, 'title', None))

                            if autor and autor != "None":
                                metadados_extras.append(f"Autor (Legacy): {autor}")
                                extraiu_algo = True
                            if modificador and modificador != "None":
                                metadados_extras.append(f"Último a Modificar (Legacy): {modificador}")
                                extraiu_algo = True
                            if titulo and titulo != "None":
                                metadados_extras.append(f"Título Interno (Legacy): {titulo}")
                                extraiu_algo = True

                            if extrair_raw:
                                raw_dump.append("\n=== OLEFILE METADATA (RAW) ===")
                                for prop, val in meta.__dict__.items():
                                    if val:
                                        raw_dump.append(f"{prop}: {decodificar(val)}")

                            if not extraiu_algo:
                                metadados_extras.append(
                                    "ℹ️ Metadados avançados (título, autoria) não localizados ou arquivo lavado.")
                    else:
                        metadados_extras.append(
                            "⚠️ O arquivo possui extensão legada, mas não é um formato OLE válido.")
                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao ler o arquivo Office legado: {e}")
            else:
                metadados_extras.append(
                    "⚠️ Biblioteca ausente: O módulo 'olefile' não foi encontrado. Impossível analisar arquivos do Office 97-2003.")

        # 6. ATALHOS DO WINDOWS (.lnk)
        elif extensao in FORMATOS_ATALHOS:
            if HAS_LNKPARSE:
                try:
                    with open(caminho_arquivo, 'rb') as indata:
                        lnk = LnkParse3.lnk_file(indata)
                        extraiu_algo = False

                        dados = lnk.get_json()
                        if extrair_raw and dados:
                            raw_dump.append("\n=== LNKPARSE3 (RAW JSON) ===")
                            raw_dump.extend(json.dumps(dados, indent=2, ensure_ascii=False, default=str).splitlines())

                        info_link = dados.get('link_info', {})
                        if info_link:
                            caminho_base = info_link.get('local_base_path')
                            if caminho_base:
                                metadados_extras.append(f"Caminho Alvo (Local): {caminho_base}")
                                extraiu_algo = True

                            loc_info = info_link.get('location_info', {})
                            if loc_info:
                                vol_label = loc_info.get('volume_label')
                                if vol_label:
                                    metadados_extras.append(f"Rótulo do Volume: {vol_label}")
                                    extraiu_algo = True

                                serial = loc_info.get('drive_serial_number')
                                if serial:
                                    if isinstance(serial, int):
                                        serial_fmt = hex(serial).upper().replace('0X', '')
                                    else:
                                        serial_fmt = str(serial).upper()
                                    metadados_extras.append(f"Serial do Volume (Hex): {serial_fmt}")
                                    extraiu_algo = True

                        info_dados = dados.get('data', {})
                        if info_dados:
                            caminho_relativo = info_dados.get('relative_path')
                            if caminho_relativo:
                                metadados_extras.append(f"Caminho Alvo (Relativo): {caminho_relativo}")
                                extraiu_algo = True

                            dir_trab = info_dados.get('working_dir')
                            if dir_trab:
                                metadados_extras.append(f"Diretório de Trabalho: {dir_trab}")
                                extraiu_algo = True

                            args = info_dados.get('command_line_arguments')
                            if args:
                                metadados_extras.append(f"Argumentos (Execução): {args}")
                                extraiu_algo = True

                            desc = info_dados.get('description') or info_dados.get('name_string')
                            if desc:
                                metadados_extras.append(f"Descrição/Nome Interno: {desc}")
                                extraiu_algo = True

                        info_extra = dados.get('extra_data', {})
                        tracker = info_extra.get('TRACKER_DATA_BLOCK', {})
                        mac = tracker.get('mac_address')
                        if mac:
                            metadados_extras.append(f"MAC Address de Origem: {mac}")
                            extraiu_algo = True
                        else:
                            metadados_extras.append("MAC Address de Origem: [Não localizado neste atalho]")

                        if not extraiu_algo:
                            metadados_extras.append(
                                "ℹ️ O alvo deste atalho está ofuscado ou aponta para um item virtual do Windows (Shell Item ID).")
                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao analisar atalho .lnk: {e}")
            else:
                metadados_extras.append(
                    "⚠️ Biblioteca ausente: O módulo 'LnkParse3' não foi encontrado. Análise de atalhos indisponível.")

        # 7. EXECUTÁVEIS E DLLs (.exe, .dll, .sys)
        elif extensao in FORMATOS_EXECUTAVEIS:
            if HAS_PEFILE:
                try:
                    pe = pefile.PE(caminho_arquivo)
                    if extrair_raw:
                        raw_dump.append("\n=== PEFILE (RAW INFO) ===")
                        try:
                            linhas_limpas = [linha.strip() for linha in pe.dump_info().splitlines() if
                                             linha.strip()]
                            bloco_gigante = "\n".join(linhas_limpas)
                            raw_dump.append(bloco_gigante)
                        except Exception:
                            pass

                    timestamp = pe.FILE_HEADER.TimeDateStamp
                    data_compilacao = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).strftime(
                        '%d/%m/%Y %H:%M:%S UTC')
                    metadados_extras.append(f"Data de Compilação (TimeDateStamp): {data_compilacao}")

                    try:
                        dir_seguranca = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
                        if dir_seguranca.VirtualAddress > 0 and dir_seguranca.Size > 0:
                            metadados_extras.append(
                                "Assinatura Digital: ✅ PRESENTE (Contém certificado Authenticode)")
                        else:
                            metadados_extras.append(
                                "Assinatura Digital: ⚠️ AUSENTE (Arquivo não assinado - Suspeito se disser ser do Windows/Microsoft)")
                    except Exception:
                        metadados_extras.append("Assinatura Digital: [Erro ao verificar]")

                    if hasattr(pe, 'FileInfo'):
                        for fileinfo in pe.FileInfo:
                            for info in fileinfo:
                                if hasattr(info, 'StringTable'):
                                    for st in info.StringTable:
                                        for entrada in st.entries.items():
                                            chave = entrada[0].decode('utf-8', errors='ignore')
                                            valor = entrada[1].decode('utf-8', errors='ignore')
                                            if chave in ['OriginalFilename', 'CompanyName', 'FileDescription']:
                                                metadados_extras.append(f"{chave}: {valor}")


                except Exception as e:
                    msg_erro = str(e)

                    # Intercepta especificamente o erro de cabeçalho NE do pefile
                    if 'Invalid NT Headers signature' in msg_erro:
                        arquitetura = identificar_arquitetura_executavel(caminho_arquivo)

                        if arquitetura == "NE (16-bits Legado - Windows 3.x)":
                            metadados_extras.append(
                                "ℹ️ Executável Legado de 16-bits (Formato NE). Extração de metadados internos não suportada, mas integridade e hashes garantidos.")
                        else:
                            metadados_extras.append(f"⚠️ Erro ao ler metadados do PE: {msg_erro}")
                    else:
                        # Se for outro erro de PE, exibe normalmente
                        metadados_extras.append(f"⚠️ Erro ao ler metadados do PE (Executável): {msg_erro}")
            else:
                metadados_extras.append(
                    "⚠️ Biblioteca ausente: O módulo 'pefile' não foi encontrado. Impossível extrair dados do executável.")

        # 8. E-MAILS EXPORTADOS (.eml, .msg)
        elif extensao in FORMATOS_EMAIL_EML:
            try:
                with open(caminho_arquivo, 'rb') as f:
                    msg = BytesParser(policy=policy.default).parse(f)
                    extraiu_algo = False

                    if extrair_raw:
                        raw_dump.append("\n=== EMAIL HEADERS (RAW) ===")
                        for k, v in msg.items():
                            raw_dump.append(f"{k}: {v}")

                    if msg['from']:
                        metadados_extras.append(f"Remetente: {msg['from']}")
                        extraiu_algo = True
                    if msg['to']:
                        metadados_extras.append(f"Destinatário: {msg['to']}")
                        extraiu_algo = True
                    if msg['subject']:
                        metadados_extras.append(f"Assunto: {msg['subject']}")
                        extraiu_algo = True
                    if msg['date']:
                        metadados_extras.append(f"Data de Envio: {msg['date']}")
                        extraiu_algo = True

                    received = msg.get_all('Received')
                    if received:
                        metadados_extras.append(
                            f"1º Servidor de Trânsito (Origem): {received[-1].split(';')[-1].strip()}")
                        extraiu_algo = True

                    if not extraiu_algo:
                        metadados_extras.append(
                            "ℹ️ Cabeçalhos de e-mail (Remetente, Destinatário, Assunto) não localizados ou arquivo malformado.")

            except Exception as e:
                metadados_extras.append(f"⚠️ Erro ao analisar estrutura do e-mail (.eml): {e}")

        elif extensao in FORMATOS_EMAIL_MSG:
            if HAS_EXTRACT_MSG:
                try:
                    msg = extract_msg.Message(caminho_arquivo)
                    extraiu_algo = False

                    if extrair_raw:
                        raw_dump.append("\n=== EXTRACT_MSG (RAW) ===")
                        for k, v in msg.header.items():
                            raw_dump.append(f"{k}: {v}")

                    if msg.sender:
                        metadados_extras.append(f"Remetente (MSG): {msg.sender}")
                        extraiu_algo = True
                    if msg.to:
                        metadados_extras.append(f"Destinatário (MSG): {msg.to}")
                        extraiu_algo = True
                    if msg.subject:
                        metadados_extras.append(f"Assunto (MSG): {msg.subject}")
                        extraiu_algo = True
                    if msg.date:
                        metadados_extras.append(f"Data de Envio (MSG): {msg.date}")
                        extraiu_algo = True

                    msg.close()

                    if not extraiu_algo:
                        metadados_extras.append(
                            "ℹ️ Propriedades do Outlook (Remetente, Assunto) vazias neste arquivo.")

                except Exception as e:
                    metadados_extras.append(f"⚠️ Erro ao ler metadados do Outlook (.msg): {e}")
            else:
                metadados_extras.append(
                    "⚠️ Biblioteca ausente: O módulo 'extract_msg' não foi encontrado. Impossível ler e-mails nativos do Outlook (.msg).")

        # 9. ARQUIVOS DE ÁUDIO (TinyTag primário + ExifTool Complementar/Fallback)
        elif extensao in FORMATOS_AUDIO:
            extraiu_algo = False
            caminho_exiftool = None

            # --- TENTATIVA 1: TinyTag (Extremamente rápido para MP3, WAV, M4A) ---
            if HAS_TINYTAG:
                try:
                    tag = TinyTag.get(caminho_arquivo)
                    if extrair_raw:
                        raw_dump.append("\n=== TINYTAG (RAW) ===")
                        for k, v in tag.as_dict().items():
                            if v is not None:
                                raw_dump.append(f"{k}: {v}")

                    if tag.duration is not None:
                        mins, secs = divmod(tag.duration, 60)
                        horas, mins = divmod(mins, 60)
                        metadados_extras.append(f"Duração Exata: {int(horas):02d}:{int(mins):02d}:{int(secs):02d}")
                        extraiu_algo = True
                    if tag.bitrate:
                        metadados_extras.append(f"Bitrate: {int(tag.bitrate)} kbps")
                        extraiu_algo = True
                    if tag.artist:
                        metadados_extras.append(f"Artista/Criador: {tag.artist}")
                        extraiu_algo = True
                    if tag.comment:
                        metadados_extras.append(f"Comentários: {tag.comment}")
                        extraiu_algo = True
                except Exception:
                    pass

            # --- TENTATIVA 2: ExifTool (Formatos exóticos ou Dump complementar) ---
            if not extraiu_algo or extrair_raw:
                caminho_exiftool = obter_caminho_exiftool()
                if caminho_exiftool:
                    try:
                        cmd = [caminho_exiftool, "-charset", "filename=latin", "-charset", "utf8", "-j", "-G", "-a", "-ee", "-api", "largefilesupport=1", "-c", "%+.6f", caminho_arquivo]
                        processo = subprocess.run(
                            cmd, capture_output=True, encoding='utf-8', errors='replace', timeout=15,
                            creationflags=0x08000000 if os.name == 'nt' else 0
                        )

                        if processo.returncode == 0:
                            dados_json = json.loads(processo.stdout)
                            if dados_json:
                                meta = dados_json[0]
                                exiftool_executado = True
                                if extrair_raw:
                                    raw_dump.append("\n=== EXIFTOOL (RAW) ===")
                                    for key_raw, val_raw in meta.items():
                                        raw_dump.append(f"{key_raw}: {val_raw}")

                                extraiu_pelo_exiftool = False

                                duracao = meta.get('Composite:Duration') or meta.get('System:Duration')
                                if duracao and not extraiu_algo:
                                    metadados_extras.append(f"Duração (ExifTool): {duracao}")
                                    extraiu_pelo_exiftool = True

                                artista = None
                                for chave, valor in meta.items():
                                    if chave.endswith(':Artist') or chave.endswith(':Author') or chave.endswith(
                                            ':Creator'):
                                        artista = valor
                                        break

                                if artista and not extraiu_algo:
                                    metadados_extras.append(f"Autor/Criador (ExifTool): {artista}")
                                    extraiu_pelo_exiftool = True

                                if not extraiu_pelo_exiftool and not extraiu_algo:
                                    metadados_extras.append(
                                        "ℹ️ Formato lido pelo ExifTool, mas nenhum dado de autoria ou duração encontrado.")
                                else:
                                    extraiu_algo = True

                    except subprocess.TimeoutExpired:
                        nome_arq = os.path.basename(caminho_arquivo)
                        metadados_extras.append("⚠️ EXIFTOOL ABORTADO: Tempo limite de 15s excedido (Prevenção de travamento).")
                        metadados_extras.append("   ↳ O áudio possui estrutura complexa para processamento em lote.")
                        metadados_extras.append("   ↳ ORIENTAÇÃO PERICIAL: Realize a extração manualmente. Abra o CMD/PowerShell na pasta do arquivo e execute:")
                        metadados_extras.append(f"   ↳ Comando: exiftool -j -G \"{nome_arq}\" > dump_metadados.json")
                    except Exception as e:
                        metadados_extras.append(f"⚠️ Erro no ExifTool para áudio: {e}")
                else:
                    if not HAS_TINYTAG:
                        metadados_extras.append(
                            "⚠️ Bibliotecas TinyTag e ExifTool ausentes. Extração de áudio impossível.")
                    elif not extraiu_algo:
                        metadados_extras.append(
                            "ℹ️ Formato de áudio não suportado nativamente e ExifTool ausente para tentar leitura secundária.")

            if not extraiu_algo and HAS_TINYTAG and caminho_exiftool:
                metadados_extras.append(
                    "ℹ️ O arquivo foi analisado com sucesso, mas não contém metadados de autoria ou duração legíveis.")

        # 10. ARQUIVOS GEOGRÁFICOS (KML e KMZ)
        elif extensao in FORMATOS_KML:
            try:
                # --- NOVO BLOCO PARA SUPORTE A KMZ ---
                if extensao == 'kmz':
                    with zipfile.ZipFile(caminho_arquivo, 'r') as z:
                        # Procura o primeiro arquivo .kml dentro do arquivo zipado
                        kml_interno = next((nome for nome in z.namelist() if nome.lower().endswith('.kml')), None)
                        if kml_interno:
                            with z.open(kml_interno, 'r') as f_kml:
                                tree = ET.parse(f_kml)
                                root = tree.getroot()
                        else:
                            metadados_extras.append(
                                "⚠️ Erro ao ler KMZ: Nenhum arquivo KML válido encontrado dentro do pacote.")
                            root = None
                else:
                    tree = ET.parse(caminho_arquivo)
                    root = tree.getroot()
                # -------------------------------------

                if root is not None:
                    pontos_encontrados = 0
                    pontos_vistos = set()  # Controle para ignorar pontos repetidos

                    # Itera ignorando namespaces dinâmicos (que variam muito em KMLs)
                    for elem in root.iter():
                        tag_name = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag

                        if tag_name == 'coordinates' and elem.text:
                            # Em KML, múltiplas coordenadas num polígono são separadas por espaço
                            coords = elem.text.strip().split()

                            for coord in coords:
                                partes = coord.split(',')
                                if len(partes) >= 2:
                                    try:
                                        # O padrão KML inverte a ordem: Longitude primeiro, Latitude depois
                                        lon = float(partes[0])
                                        lat = float(partes[1])

                                        # Cria uma string padronizada do ponto para checar duplicatas
                                        str_ponto = f"{lat:.6f},{lon:.6f}"

                                        # Só adiciona se o ponto for inédito neste arquivo
                                        if str_ponto not in pontos_vistos:
                                            pontos_vistos.add(str_ponto)
                                            pontos_encontrados += 1

                                            # Vai TUDO para o relatório e para a memória
                                            metadados_extras.append(
                                                f"📍 GPS (Latitude, Longitude): {lat:.6f}, {lon:.6f}")
                                            link_maps = f"https://www.google.com/maps/search/?api=1&query={lat:.6f},{lon:.6f}"
                                            metadados_extras.append(f"   ↳ Visualizar no Mapa: {link_maps}")
                                    except ValueError:
                                        pass

                    if pontos_encontrados == 0:
                        metadados_extras.append(
                            "ℹ️ Nenhuma coordenada geográfica (Point/coordinates) encontrada na estrutura deste arquivo.")
                    else:
                        # Um aviso amigável indicando quantos vértices compõem a área geométrica
                        metadados_extras.append(
                            f"\n🗺️ Total exato de vértices/pontos únicos mapeados: {pontos_encontrados}")

                    if extrair_raw:
                        raw_dump.append("\n=== KML/KMZ (RAW) ===")
                        raw_dump.append(f"Total de coordenadas únicas extraídas: {pontos_encontrados}")

            except zipfile.BadZipFile:
                metadados_extras.append(
                    "⚠️ Erro ao ler KMZ: O arquivo está corrompido ou não é um pacote ZIP válido.")
            except ET.ParseError:
                metadados_extras.append(
                    "⚠️ Erro ao ler KML/KMZ: A estrutura XML do arquivo está malformada ou corrompida.")
            except Exception as e:
                metadados_extras.append(f"⚠️ Erro ao extrair dados do arquivo geográfico: {e}")

        # 11. COMPACTADOS, TORRENTS E RTF (Lidos via ExifTool)
        elif extensao in (FORMATOS_COMPACTADOS + FORMATOS_TORRENT + FORMATOS_RTF):
            caminho_exiftool = obter_caminho_exiftool()
            if caminho_exiftool:
                try:
                    cmd = [caminho_exiftool, "-charset", "filename=latin", "-charset", "utf8", "-j", "-G", "-a", "-ee", "-api", "largefilesupport=1", "-c", "%+.6f", caminho_arquivo]
                    processo = subprocess.run(cmd, capture_output=True, encoding='utf-8', errors='replace',
                                              timeout=15,
                                              creationflags=0x08000000 if os.name == 'nt' else 0)

                    if processo.returncode == 0:
                        dados_json = json.loads(processo.stdout)
                        if dados_json:
                            meta = dados_json[0]
                            exiftool_executado = True
                            if extrair_raw:
                                raw_dump.append("\n=== EXIFTOOL (RAW) ===")
                                for key_raw, val_raw in meta.items():
                                    raw_dump.append(f"{key_raw}: {val_raw}")
                            extraiu_algo = False

                            comentario = meta.get('ZIP:Comment') or meta.get('Bencode:Comment')
                            if comentario:
                                metadados_extras.append(f"Comentário Embutido: {comentario}")
                                extraiu_algo = True

                            criador = meta.get('RTF:Author') or meta.get('Bencode:CreatedBy')
                            if criador:
                                metadados_extras.append(f"Autor/Criador: {criador}")
                                extraiu_algo = True

                            data_criacao = meta.get('Bencode:CreationDate')
                            if data_criacao:
                                metadados_extras.append(f"Data de Criação (Interna): {data_criacao}")
                                extraiu_algo = True

                            if not extraiu_algo:
                                metadados_extras.append("ℹ️ Metadados avançados não localizados.")
                                metadados_extras.append(
                                    "   ↳ O ExifTool analisou o arquivo, mas não encontrou informações de autoria ou comentários suportados para este formato. A estrutura interna permanece preservada.")


                except subprocess.TimeoutExpired:
                    nome_arq = os.path.basename(caminho_arquivo)
                    metadados_extras.append("⚠️ EXIFTOOL ABORTADO: Tempo limite de 15s excedido (Prevenção de travamento).")
                    metadados_extras.append("   ↳ O arquivo compactado/documento é muito grande para processamento em lote.")
                    metadados_extras.append("   ↳ ORIENTAÇÃO PERICIAL: Realize a extração manualmente. Abra o CMD/PowerShell na pasta do arquivo e execute:")
                    metadados_extras.append(f"   ↳ Comando: exiftool -j -G \"{nome_arq}\" > dump_metadados.json")
                except Exception as e:
                    metadados_extras.append(
                        f"⚠️ Erro inesperado ao processar arquivo compactado/documento com ExifTool: {e}")
            else:
                pasta_esperada = "exiftool-13.59_64" if sys.maxsize > 2 ** 32 else "exiftool-13.59_32"
                metadados_extras.append(
                    f"⚠️ ExifTool ausente: Não foi possível extrair metadados estruturais, criadores ou comentários do arquivo compactado/documento. Pasta esperada: '{pasta_esperada}'.")

        # =====================================================================
        # EXIFTOOL UNIVERSAL COMPLEMENTAR (Rede de Captura Final)
        # Se extrair_raw estiver ligado e o ExifTool ainda não tiver rodado neste arquivo, roda agora.
        # =====================================================================
        if extrair_raw and not exiftool_executado:
            caminho_exiftool_complementar = obter_caminho_exiftool()
            if caminho_exiftool_complementar:
                try:
                    cmd_comp = [caminho_exiftool_complementar, "-charset", "filename=latin", "-charset", "utf8", "-j", "-G", "-a", "-ee", "-api", "largefilesupport=1", "-c", "%+.6f", caminho_arquivo]
                    proc_comp = subprocess.run(
                        cmd_comp, capture_output=True, encoding='utf-8', errors='replace', timeout=15,
                        creationflags=0x08000000 if os.name == 'nt' else 0
                    )

                    if proc_comp.returncode == 0:
                        json_comp = json.loads(proc_comp.stdout)
                        if json_comp:
                            meta_comp = json_comp[0]
                            raw_dump.append("\n=== EXIFTOOL (RAW DUMP COMPLEMENTAR) ===")
                            for k_raw, v_raw in meta_comp.items():
                                raw_dump.append(f"{k_raw}: {v_raw}")

                except subprocess.TimeoutExpired:
                    nome_arq = os.path.basename(caminho_arquivo)
                    raw_dump.append("\n=== EXIFTOOL (FALHA) ===")
                    raw_dump.append("⚠️ TEMPO LIMITE EXCEDIDO (>15s).")
                    raw_dump.append("↳ ORIENTAÇÃO PERICIAL: O arquivo causou timeout. Para forçar a extração bruta, use o PowerShell:")
                    raw_dump.append(f"↳ Comando: exiftool -j -G \"{nome_arq}\" > dump_metadados.json")
                except Exception:
                    # Falha silenciosa para outros erros genéricos da rede de captura
                    pass

        # --- MONTAGEM DO RAW DUMP NO FINAL DO RELATÓRIO DO ARQUIVO ---
        if extrair_raw and raw_dump:
            metadados_extras.append("")
            metadados_extras.append("=== TODOS OS METADADOS (RAW DUMP) ===")
            metadados_extras.extend(raw_dump)

        return metadados_extras

    def obter_metadados_e_hashes(self, caminho_arquivo, algos_selecionados, extrair_metadados=False):
        try:
            # --- PROTEÇÃO FORENSE: BLOQUEIO DE ARQUIVOS EM NUVEM E ACESSO ---
            # Usa o lstat seguro no lugar do stat antigo
            stat_info = os.lstat(caminho_arquivo)

            if os.name == 'nt':
                try:
                    # 1. BLOQUEIO PADRÃO MICROSOFT (OneDrive, Dropbox, iCloud)
                    if hasattr(stat_info, 'st_file_attributes'):
                        atributos = stat_info.st_file_attributes

                        if (atributos & 0x400000) or (atributos & 0x1000) or (atributos & 0x100000) or (
                                atributos & 0x40000):
                            # Checa se já perguntamos ao usuário nesta sessão
                            if getattr(self, 'ignorar_nuvem_nativa', None) is False:
                                return {
                                    'sucesso': False,
                                    'erro': 'ARQUIVO EM NUVEM DETECTADO: Atributos de "Apenas Online". Proteção mantida pelo perito.'
                                }
                            elif getattr(self, 'ignorar_nuvem_nativa', None) is None:
                                # Pausa a interface para dar o alerta forense
                                msg_box = QMessageBox(self)
                                msg_box.setWindowTitle("Aviso Forense - Atributos de Nuvem")
                                msg_box.setText(
                                    "<b>Foi detectado um arquivo com atributos de 'Nuvem / Apenas Online'.</b>")
                                msg_box.setInformativeText(
                                    "O Windows informou que este arquivo pertence a um serviço de nuvem (OneDrive, Dropbox, etc.).\n\n"
                                    "Se ele foi copiado de uma nuvem para o disco local, o Windows pode ter mantido essa marcação "
                                    "erroneamente nos atributos (herança NTFS). Mas se ele não estiver offline, a leitura forçará o download.\n\n"
                                    "Você garante que o arquivo é local e deseja ignorar essa proteção para forçar a extração deste e de TODOS os demais arquivos na mesma situação neste lote?"
                                )
                                msg_box.setIcon(QMessageBox.Icon.Warning)

                                btn_sim = msg_box.addButton("Sim, forçar para todos do lote",
                                                            QMessageBox.ButtonRole.AcceptRole)
                                btn_nao = msg_box.addButton("Não, manter bloqueio para todos",
                                                            QMessageBox.ButtonRole.RejectRole)

                                msg_box.exec()

                                if msg_box.clickedButton() == btn_sim:
                                    self.ignorar_nuvem_nativa = True
                                else:
                                    self.ignorar_nuvem_nativa = False
                                    return {
                                        'sucesso': False,
                                        'erro': 'ARQUIVO EM NUVEM DETECTADO: Atributos de "Apenas Online". Proteção mantida pelo perito.'
                                    }
                            # Se self.ignorar_nuvem_nativa for True, ele passa reto aqui e extrai o arquivo
                except OSError as e:
                    return {'sucesso': False, 'erro': f'ACESSO NEGADO PELO S.O.: {e}'}

                # 2. BLOQUEIO DE DISCO VIRTUAL VFS (Google Drive em modo Streaming)
                try:
                    drive = os.path.splitdrive(caminho_arquivo)[0] + "\\"
                    if len(drive) >= 3:
                        info_vol = obter_info_volume(drive)
                        if info_vol:
                            rotulo = info_vol.get('rotulo', '').lower()
                            fs = info_vol.get('sistema_arquivos', '').upper()

                            if 'google drive' in rotulo or 'cbfs' in fs:
                                # Checa se já perguntamos pro usuário nesta sessão
                                if getattr(self, 'ignorar_google_drive', None) is False:
                                    return {
                                        'sucesso': False,
                                        'erro': f'DISCO VIRTUAL EM NUVEM DETECTADO ({rotulo.upper()}): Proteção mantida pelo perito. Leitura bloqueada preventivamente.'
                                    }
                                elif getattr(self, 'ignorar_google_drive', None) is None:
                                    # Pausa a interface para dar o alerta forense ao perito
                                    msg_box = QMessageBox(self)
                                    msg_box.setWindowTitle("Risco Forense - Google Drive Detectado")
                                    msg_box.setText("<b>Foi detectada uma origem de disco virtual do Google Drive.</b>")
                                    msg_box.setInformativeText(
                                        "O driver de disco virtual do Google Drive oculta o status real do arquivo. Se a evidência "
                                        "não estiver totalmente baixada no seu cache local, o Extrator forçará o download "
                                        "automático da internet durante a leitura, gerando tráfego de rede indesejado.\n\n"
                                        "Como Perito, deseja ignorar a proteção de nuvem e extrair os hashes assim mesmo "
                                        "(assumindo o risco de download)?"
                                    )
                                    msg_box.setIcon(QMessageBox.Icon.Warning)

                                    btn_sim = msg_box.addButton("Sim, ignorar proteção e extrair",
                                                                QMessageBox.ButtonRole.AcceptRole)
                                    btn_nao = msg_box.addButton("Não, manter bloqueio seguro",
                                                                QMessageBox.ButtonRole.RejectRole)

                                    msg_box.exec()

                                    if msg_box.clickedButton() == btn_sim:
                                        self.ignorar_google_drive = True
                                    else:
                                        self.ignorar_google_drive = False
                                        return {
                                            'sucesso': False,
                                            'erro': f'DISCO VIRTUAL EM NUVEM DETECTADO ({rotulo.upper()}): Proteção mantida pelo perito. Leitura bloqueada preventivamente.'
                                        }
                                # Se self.ignorar_google_drive for True, ele passa reto aqui e extrai o arquivo
                except Exception:
                    pass
            # -------------------------------------------------------------------

            # Reaproveita as informações já extraídas de forma segura com o os.lstat()
            tamanho_bytes = stat_info.st_size
            tamanho_mb = tamanho_bytes / (1024 * 1024)
            data_modificacao_raw = stat_info.st_mtime
            data_modificacao = datetime.datetime.fromtimestamp(data_modificacao_raw).strftime('%d/%m/%Y %H:%M:%S')

            objetos_hash = {}
            if "CRC32" in algos_selecionados: objetos_hash["CRC32"] = 0
            if "MD5" in algos_selecionados: objetos_hash["MD5"] = hashlib.md5()
            if "SHA-1" in algos_selecionados: objetos_hash["SHA-1"] = hashlib.sha1()
            if "SHA-256" in algos_selecionados: objetos_hash["SHA-256"] = hashlib.sha256()
            if "SHA-384" in algos_selecionados: objetos_hash["SHA-384"] = hashlib.sha384()
            if "SHA-512" in algos_selecionados: objetos_hash["SHA-512"] = hashlib.sha512()

            # Inicializa o contador para entropia de Shannon apenas se solicitado
            contagem_bytes = Counter() if extrair_metadados else None

            self.barra_arquivo.setMaximum(100)
            self.barra_arquivo.setValue(0)
            bytes_processados = 0
            tamanho_chunk = 65536

            try:
                with open(caminho_arquivo, 'rb') as f:
                    # --- INÍCIO DO FILE LOCK ---
                    if os.name == 'nt' and tamanho_bytes > 0:  # Só tranca se tiver conteúdo
                        try:
                            # Tenta trancar o primeiro 1 byte do arquivo (simbolicamente)
                            # O modo LK_NBLCK (Non-Blocking Lock) falha imediatamente se o arquivo estiver em uso
                            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                        except OSError:
                            return {'sucesso': False,
                                    'erro': 'ARQUIVO EM USO: Modificação ativa detectada. Leitura abortada por segurança pericial.'}
                    # ---------------------------
                    try:
                        while True:
                            chunk = f.read(tamanho_chunk)
                            if not chunk:  # Se retornou vazio (fim do arquivo), quebra o loop
                                break

                            if self.cancelar_operacao:
                                return {'sucesso': False, 'erro': 'OPERAÇÃO CANCELADA PELO USUÁRIO'}

                            for algo in algos_selecionados:
                                if algo == "CRC32":
                                    objetos_hash["CRC32"] = zlib.crc32(chunk, objetos_hash["CRC32"])
                                else:
                                    objetos_hash[algo].update(chunk)

                            # Conta a frequência dos bytes para entropia de Shannon apenas se os metadados foram solicitados
                            if contagem_bytes is not None:
                                contagem_bytes.update(chunk)

                            bytes_processados += len(chunk)

                            self.bytes_processados_total += len(chunk)

                            if bytes_processados % (tamanho_chunk * 16) == 0:
                                percentual = int((bytes_processados / tamanho_bytes) * 100) if tamanho_bytes > 0 else 100
                                self.barra_arquivo.setValue(percentual)
                                QApplication.processEvents()
                    finally:
                        # --- FIM DO FILE LOCK ---
                        if os.name == 'nt' and tamanho_bytes > 0:
                            try:
                                # Destranca o arquivo retornando o ponteiro para o início
                                f.seek(0)
                                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                            except Exception:
                                pass
            except PermissionError:
                # Captura a falha ANTES mesmo do arquivo abrir (ex: aberto no Word/Excel ou falta de privilégios)
                return {'sucesso': False,
                        'erro': 'ACESSO NEGADO / ARQUIVO EM USO: O sistema operacional bloqueou a leitura (arquivo aberto em outro programa ou falta de privilégios de Administrador).'}
            except OSError as e:
                # Tratamento explícito para falhas físicas/corrupção (Erro 22, 23, etc.)
                return {'sucesso': False,
                        'erro': f'ERRO DE DISCO/CORRUPÇÃO (Código {e.errno}): O Windows abortou a leitura. Possível dano físico no setor do disco ou sistema de arquivos corrompido.'}

            except Exception as e:
                return {'sucesso': False, 'erro': repr(e)}

            self.barra_arquivo.setValue(100)

            # --- CÁLCULO DA ENTROPIA DE SHANNON ---
            resultado_entropia = None

            if extrair_metadados:
                entropia = 0.0
                if tamanho_bytes > 0:
                    for contagem in contagem_bytes.values():
                        probabilidade = contagem / tamanho_bytes
                        entropia -= probabilidade * math.log2(probabilidade)

                # Identifica a extensão para evitar falsos positivos de compressão natural
                _, ext_arquivo = os.path.splitext(caminho_arquivo)
                ext_arquivo = ext_arquivo.lower().replace('.', '')
                formatos_comprimidos = ['jpg', 'jpeg', 'png', 'webp', 'gif', 'zip', 'rar', '7z', 'gz', 'mp4', 'mkv', 'avi',
                                        'mp3', 'm4a', 'pdf']

                status_entropia = ""
                if entropia > 7.9:
                    if ext_arquivo in formatos_comprimidos:
                        status_entropia = " (Normal para o formato comprimido deste arquivo)"
                    else:
                        status_entropia = " (⚠️ ALERTA: Alta entropia - Possível Criptografia / Arquivo Packed)"
                elif entropia < 1.0:
                    status_entropia = " (Baixa entropia - Arquivo altamente repetitivo ou vazio)"
                else:
                    # --- Mensagem para a faixa normal (entre 1.0 e 7.9) ---
                    status_entropia = " (Entropia normal - Sem indícios de ofuscação ou criptografia)"

                resultado_entropia = f"{entropia:.4f}{status_entropia}"
            # --------------------------------------------

            resultados_hash = {}
            for algo in algos_selecionados:
                if algo == "CRC32":
                    # O 'X' maiúsculo no final da formatação já converte para maiúsculas
                    resultados_hash["CRC32"] = f"{objetos_hash['CRC32'] & 0xFFFFFFFF:08X}"
                else:
                    # O .upper() converte o resultado do hexdigest para maiúsculas
                    resultados_hash[algo] = objetos_hash[algo].hexdigest().upper()

            # --- DETECÇÃO DE ARQUIVO VAZIO ATRAVÉS DOS HASHES ---
            hashes_arquivo_vazio = {
                "CRC32": "00000000",
                "MD5": "D41D8CD98F00B204E9800998ECF8427E",
                "SHA-1": "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
                "SHA-256": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                "SHA-384": "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B",
                "SHA-512": "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E",
            }

            arquivo_vazio_detectado = False
            for algoritmo, hash_esperado in hashes_arquivo_vazio.items():
                if algoritmo in resultados_hash and resultados_hash[algoritmo] == hash_esperado:
                    arquivo_vazio_detectado = True
                    break

            return {
                'sucesso': True,
                'hashes': resultados_hash,
                'bytes': tamanho_bytes,
                'mb': tamanho_mb,
                'data': data_modificacao,
                'entropia': resultado_entropia,
                'arquivo_vazio': arquivo_vazio_detectado
            }
        except Exception as e:
            return {'sucesso': False, 'erro': repr(e)}

    # --- EVENTOS DE DRAG AND DROP ---
    def dragEnterEvent(self, event):
        if self.processando:
            event.ignore()
            return
        if event.mimeData().hasUrls():
            # Salva o estilo original do Grupo de Saída e adiciona o destaque azul
            if not hasattr(self, '_estilo_grupo_saida_anterior'):
                self._estilo_grupo_saida_anterior = self.grupo_saida.styleSheet()

            # Aplica CSS direcionado ao QGroupBox para não bagunçar os elementos internos
            self.grupo_saida.setStyleSheet(
                self._estilo_grupo_saida_anterior + " QGroupBox { border: 2px dashed #0078D7; background-color: rgba(0, 120, 215, 0.05); }")

            event.acceptProposedAction()

    def dragMoveEvent(self, event):
        if self.processando:
            event.ignore()
            return
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragLeaveEvent(self, event):
        # Se o mouse sair da janela (ou entrar na área de Custódia), removemos o destaque azul
        if hasattr(self, '_estilo_grupo_saida_anterior'):
            self.grupo_saida.setStyleSheet(self._estilo_grupo_saida_anterior)
            del self._estilo_grupo_saida_anterior
        super().dragLeaveEvent(event)

    def perguntar_incluir_subdiretorios(self):
        """Exibe uma caixa de diálogo perguntando se o usuário deseja varrer subdiretórios."""
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Escopo da Extração")
        msg_box.setText("Você adicionou um diretório ou unidade na área de extração.")
        msg_box.setInformativeText(
            "Deseja varrer recursivamente todas as pastas internas (subdiretórios) em busca de arquivos?")
        msg_box.setIcon(QMessageBox.Icon.Question)

        btn_sim = msg_box.addButton("Sim, incluir subdiretórios", QMessageBox.ButtonRole.AcceptRole)
        btn_nao = msg_box.addButton("Não, apenas o diretório raiz", QMessageBox.ButtonRole.ActionRole)
        btn_cancelar = msg_box.addButton("Cancelar Extração", QMessageBox.ButtonRole.RejectRole)

        msg_box.exec()

        # Avalia a resposta do usuário
        if msg_box.clickedButton() == btn_sim:
            return True
        elif msg_box.clickedButton() == btn_nao:
            return False
        else:
            # Se clicou em 'Cancelar' ou fechou a janela no 'X'
            return None

    def dropEvent(self, event):
        # Remove o destaque visual da janela logo que a ação for concluída
        if hasattr(self, '_estilo_grupo_saida_anterior'):
            self.grupo_saida.setStyleSheet(self._estilo_grupo_saida_anterior)
            del self._estilo_grupo_saida_anterior

        if self.processando:
            return
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            caminhos = [url.toLocalFile() for url in urls]

            event.acceptProposedAction()

            # --- NOVA LÓGICA DE INTERCEPTAÇÃO DE UNIDADE RAIZ ---
            # Só analisa se o usuário arrastar exatamente 1 item
            if len(caminhos) == 1:
                caminho = caminhos[0]
                drive, tail = os.path.splitdrive(caminho)

                # Verifica se é uma raiz de drive no Windows (ex: "D:/", "E:\")
                if drive and tail in ('/', '\\', ''):
                    caminho_raiz = drive.upper() + "\\"  # Normaliza para o padrão (ex: "D:\")

                    msg_box = QMessageBox(self)
                    msg_box.setWindowTitle("Análise de Unidade Inteira (RAW)")
                    msg_box.setText(f"Você arrastou a unidade raiz: <b>{caminho_raiz}</b>")
                    msg_box.setInformativeText("Como deseja processar esta evidência?")
                    msg_box.setIcon(QMessageBox.Icon.Question)

                    btn_arquivos = msg_box.addButton("Extrair Hashes dos Arquivos", QMessageBox.ButtonRole.ActionRole)
                    btn_raw = msg_box.addButton("Extrair Hash RAW (Bit-a-bit)", QMessageBox.ButtonRole.ActionRole)
                    btn_cancelar = msg_box.addButton("Cancelar", QMessageBox.ButtonRole.RejectRole)

                    # --- APLICANDO O ESTILO VISUAL AO BOTÃO RAW ---
                    is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()

                    if is_dark:
                        btn_raw.setStyleSheet("""
                                                QPushButton { 
                                                    font-weight: bold; 
                                                    color: #ff6666; 
                                                    background-color: #3c3f41; 
                                                    border: 1px solid #ff6666;
                                                    border-radius: 4px;
                                                    padding: 6px;
                                                }
                                                QPushButton:hover { background-color: #4b4d4f; }
                                                QPushButton:pressed { background-color: #2b2b2b; }
                                            """)
                    else:
                        btn_raw.setStyleSheet("""
                                                QPushButton {
                                                    font-weight: bold; 
                                                    color: #800000; 
                                                    background-color: #e6e6e6;
                                                    border: 1px solid #cccccc;
                                                    border-radius: 4px;
                                                    padding: 6px;
                                                }
                                                QPushButton:hover { background-color: #d4d4d4; }
                                                QPushButton:pressed { background-color: #c5c5c5; }
                                            """)

                    msg_box.exec()

                    if msg_box.clickedButton() == btn_arquivos:
                        # Pergunta sobre os subdiretórios logo após escolher extrair arquivos
                        incluir_sub = self.perguntar_incluir_subdiretorios()

                        # --- TRAVA DE CANCELAMENTO ---
                        if incluir_sub is None:
                            return

                        QTimer.singleShot(100, lambda: self.coletar_e_processar(caminhos, override_subdirs=incluir_sub))
                    elif msg_box.clickedButton() == btn_raw:
                        # Redireciona para a janela RAW, passando a raiz para pré-seleção
                        QTimer.singleShot(100,
                                          lambda: self.selecionar_unidade_raw(unidade_pre_selecionada=caminho_raiz))

                    return  # Encerra o dropEvent, pois o usuário já tomou a decisão
                    # ----------------------------------------------------

            # Comportamento padrão: Se for arquivo, pasta comum ou múltiplos itens
            # Verifica se pelo menos um dos itens arrastados é um diretório
            tem_diretorio = any(os.path.isdir(c) for c in caminhos)

            if tem_diretorio:
                incluir_sub = self.perguntar_incluir_subdiretorios()

                # --- TRAVA DE CANCELAMENTO ---
                if incluir_sub is None:
                    return

                QTimer.singleShot(100, lambda: self.coletar_e_processar(caminhos, override_subdirs=incluir_sub))
            else:
                QTimer.singleShot(100, lambda: self.coletar_e_processar(caminhos, override_subdirs=None))

    def copiar_para_area_transferencia(self):
        # Em vez de ler da interface (toPlainText), puxamos do array em memória
        conteudo = "\n".join(self._relatorio_memoria)

        if conteudo.strip() and conteudo.strip() != MENSAGEM_INICIAL:
            QApplication.clipboard().setText(conteudo)
            self.btn_copiar.setText("Copiado!")

            # Agenda a restauração do texto do botão para daqui a 1000ms (1 segundo)
            QTimer.singleShot(1000, lambda: self.btn_copiar.setText("Copiar Relatório (Ctrl+C)"))

    def salvar_relatorio(self):
        # Em vez de ler da interface (toPlainText), puxamos do array em memória
        conteudo = "\n".join(self._relatorio_memoria)

        if not conteudo.strip() or conteudo.strip() == MENSAGEM_INICIAL:
            QMessageBox.warning(self, "Aviso", "Não há relatório para ser salvo.")
            return

        agora = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # Nome padronizado para o relatório exportado
        nome_padrao = f"Relatorio_Extracao_{agora}.txt"

        opcoes_salvar = QFileDialog.Option.DontUseNativeDialog
        caminho_salvar, _ = QFileDialog.getSaveFileName(
            self,
            "Salvar Relatório",
            nome_padrao,
            "Arquivo de Texto (*.txt)",
            options=opcoes_salvar
        )

        if caminho_salvar:
            try:
                with open(caminho_salvar, 'w', encoding='utf-8') as f:
                    f.write(conteudo)

                # Feedback visual rápido de sucesso no botão
                texto_original = self.btn_salvar.text()
                self.btn_salvar.setText("Salvo com sucesso!")

                # Agenda a mudança de volta para o texto original após 1500 milissegundos
                QTimer.singleShot(1500, lambda: self.btn_salvar.setText(texto_original))

            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Ocorreu um erro ao salvar o relatório:\n{e}")

    def _salvar_relatorio_automatico(self):
        """Salva o relatório completo automaticamente no caminho pré-definido, protegendo contra queda de energia."""
        if hasattr(self, '_raw_caminho_relatorio_auto') and self._raw_caminho_relatorio_auto:
            try:
                # Puxa o conteúdo exato que está na memória
                conteudo = "\n".join(self._relatorio_memoria)
                with open(self._raw_caminho_relatorio_auto, 'w', encoding='utf-8') as f:
                    f.write(conteudo)
                self.texto_saida.append(
                    f"\n💾 Relatório completo salvo automaticamente em:\n   ↳ {self._raw_caminho_relatorio_auto}")
            except Exception as e:
                self.texto_saida.append(f"\n⚠️ Falha ao auto-salvar relatório completo: {e}")
            finally:
                # Limpa a variável para não interferir em outras extrações futuras
                self._raw_caminho_relatorio_auto = None

    def limpar_tela(self):
        # # --- LINHA TEMPORÁRIA PARA TESTAR O CRASH_LOG - FOI USADA APENAS NA FASE DE DESENVOLVIMENTO ---
        # raise RuntimeError("CRASH FORÇADO: Testando o sistema de log de erros!")
        # # ------------------------------------------------------------

        self.texto_saida.clear() # Limpa a tela e a memória
        self._relatorio_memoria.append(MENSAGEM_INICIAL + "\n")
        # noinspection PyUnresolvedReferences
        self.texto_saida._original_append(MENSAGEM_VISUAL)
        self._chars_na_tela += len(MENSAGEM_VISUAL)
        # Re-bloqueia a seleção ao limpar a tela
        self.texto_saida.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        self.barra_arquivo.setValue(0)
        self.barra_total.setValue(0)
        self.lbl_progresso_arquivo.setText("Progresso do Arquivo Atual:")

    def selecionar_arquivo(self):
        if self.processando: return

        # Combina o bloqueio de atalhos (DontResolveSymlinks) com o bloqueio da janela
        # nativa do Windows (DontUseNativeDialog) para impedir que o clique em "Abrir"
        # faça o download automático de arquivos em nuvem (OneDrive/Google Drive).
        # noinspection PyTypeChecker
        opcoes = QFileDialog.Option.DontResolveSymlinks | QFileDialog.Option.DontUseNativeDialog

        caminhos, _ = QFileDialog.getOpenFileNames(
            self,
            "Seleção Segura (Interface isolada anti-download) - Escolha o(s) arquivo(s)",
            dir=os.environ.get("SystemDrive", "C:") + "\\",
            filter="Todos os Arquivos (*)",
            options=opcoes
        )

        if caminhos:
            self.coletar_e_processar(caminhos)

    def selecionar_diretorio(self):
        if self.processando: return

        # Adicionado o DontUseNativeDialog para consistência visual com a seleção de arquivos
        # e para evitar que a navegação do Explorer tente gerar thumbnails de evidências em nuvem.
        # noinspection PyTypeChecker
        opcoes = QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontResolveSymlinks | QFileDialog.Option.DontUseNativeDialog

        diretorio = QFileDialog.getExistingDirectory(
            self,
            "Seleção Segura (Interface isolada anti-download) - Escolha o diretório",
            dir=os.environ.get("SystemDrive", "C:") + "\\",
            options=opcoes
        )

        if diretorio:
            self.coletar_e_processar([diretorio])

    def coletar_e_processar(self, caminhos_iniciais, override_subdirs=None):
        import stat  # Importado aqui para garantir o uso seguro dos atributos

        arquivos_encontrados = []

        # Se override_subdirs for fornecido (via Drag & Drop), ele sobrepõe a interface.
        # Senão, respeita o comportamento padrão da checkbox "Incluir Subdiretórios".
        if override_subdirs is not None:
            incluir_sub = override_subdirs
        else:
            incluir_sub = self.chk_subdiretorios.isChecked()

        # --- VERIFICAÇÃO: É a raiz de um Pendrive/HD? ---
        info_drive = None
        if len(caminhos_iniciais) == 1:
            # Pega o caminho exato e normaliza
            caminho_origem = os.path.abspath(caminhos_iniciais[0])

            try:
                # 1. Usa o lstat seguro em vez do falho os.path.isdir()
                st_origem = os.lstat(caminho_origem)
                if stat.S_ISDIR(st_origem.st_mode) and os.path.dirname(caminho_origem) == caminho_origem:
                    info_drive = obter_info_volume(caminho_origem)
            except OSError:
                pass
        # -----------------------------------------------------

        for caminho in caminhos_iniciais:
            # Normaliza o caminho vindo da interface
            caminho = os.path.normpath(caminho)

            try:
                # 2. Lê a "casca" do item SEM engatilhar o download em nuvem
                st_caminho = os.lstat(caminho)
            except OSError:
                continue  # Pula silenciosamente se não tiver permissão para ler

            # 3. Usa o stat seguro para decidir se é arquivo ou pasta
            if stat.S_ISREG(st_caminho.st_mode):
                arquivos_encontrados.append(caminho)
            elif stat.S_ISDIR(st_caminho.st_mode):
                if incluir_sub:
                    for raiz, _, arquivos in os.walk(caminho):
                        for arquivo in arquivos:
                            # os.walk já é seguro nativamente ao separar as listas
                            caminho_completo = os.path.normpath(os.path.join(raiz, arquivo))
                            arquivos_encontrados.append(caminho_completo)
                else:
                    for item in os.listdir(caminho):
                        caminho_completo = os.path.normpath(os.path.join(caminho, item))
                        try:
                            # 4. Proteção contra download de arquivo em nuvem ao olhar o que tem dentro da pasta raiz
                            st_item = os.lstat(caminho_completo)
                            if stat.S_ISREG(st_item.st_mode):
                                arquivos_encontrados.append(caminho_completo)
                        except OSError:
                            continue

        # --- Captura o texto colado da Cadeia de Custódia ---
        texto_custodia = ""
        # Verifica se o componente foi criado na UI antes de tentar ler
        if hasattr(self, 'texto_referencia'):
            texto_custodia = self.texto_referencia.toPlainText().strip()
        # ----------------------------------------------------------------------

            # Passa a informação do drive (se existir) para o processamento final
            self.processar_arquivos(arquivos_encontrados, info_drive, texto_custodia, caminhos_iniciais)

    def processar_arquivos(self, lista_arquivos, info_drive=None, texto_custodia="", caminhos_iniciais=None):
        # ---> CHECAGEM DE ALGORITMOS PRESENTES NA LISTA DE VALIDAÇÃO DE CADEIA DE CUSTÓDIA <---
        texto_custodia = self._verificar_pre_extracao_custodia(texto_custodia)
        if texto_custodia is None:
            return

        algos_selecionados = [algo for algo, chk in self.chk_hashes.items() if chk.isChecked()]
        total_arquivos = len(lista_arquivos)
        extrair_meta = self.chk_metadados.isChecked()
        extrair_raw = getattr(self, 'chk_metadados_raw', None) and self.chk_metadados_raw.isChecked()

        # Reseta as flags para o novo relatório (são populadas na obtenção de metadados)
        self.video_teve_fps_geral = False
        self.video_teve_fps_min_max = False

        # =========================================================================
        # PROMPT DE RESULTADOS ANTERIORES (Movido para antes da checagem de zero)
        # =========================================================================
        if len(self._relatorio_memoria) > 1:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Resultados Anteriores Encontrados")
            fonte = msg_box.font()
            fonte.setPointSize(11)
            msg_box.setFont(fonte)
            msg_box.setText("Já existem resultados de extrações anteriores na tela.")
            msg_box.setInformativeText(
                "Deseja adicionar os novos resultados à lista atual ou limpar a tela antes de começar?")
            msg_box.setIcon(QMessageBox.Icon.Question)

            btn_adicionar = msg_box.addButton("Adicionar (Manter histórico)", QMessageBox.ButtonRole.AcceptRole)
            btn_limpar = msg_box.addButton("Limpar tela e substituir", QMessageBox.ButtonRole.DestructiveRole)
            btn_cancelar = msg_box.addButton("Cancelar", QMessageBox.ButtonRole.RejectRole)

            msg_box.exec()

            if msg_box.clickedButton() == btn_cancelar:
                return
            elif msg_box.clickedButton() == btn_limpar:
                self.texto_saida.clear()
        else:
            self.texto_saida.clear()

        # =========================================================================
        # CHECAGEM DE ARQUIVOS ZERO (E CAMINHO DA PASTA)
        # =========================================================================
        if total_arquivos == 0:
            self.texto_saida.append(
                "⚠️ NENHUM ARQUIVO ENCONTRADO: O diretório (ou seleção) está vazio ou não possui arquivos válidos.")

            if caminhos_iniciais:
                for caminho in caminhos_iniciais:
                    self.texto_saida.append(f"   ↳ {caminho}")

            self.texto_saida.append("")

            scrollbar = self.texto_saida.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
            return

        self.travar_interface()

        if not algos_selecionados:
            self.texto_saida.append("[AVISO] Nenhum algoritmo de hash selecionado. Apenas metadados serão extraídos.\n")

        if extrair_meta and not HAS_PIL and not HAS_CV2 and not HAS_PYPDF:
            self.texto_saida.append("[AVISO] Nenhuma biblioteca extra detectada. Metadados avançados ignorados.\n")

        self.cancelar_operacao = False
        self.btn_cancelar.setText("CANCELAR PROCESSAMENTO")
        self.btn_cancelar.setEnabled(True)
        self.barra_total.setMaximum(total_arquivos)
        self.barra_total.setValue(0)

        # Atualiza pré-cálculo para o ETA (mantém a checagem segura anti-nuvem via os.lstat)
        self.total_bytes_processar = 0
        for arq in lista_arquivos:
            try:
                self.total_bytes_processar += os.lstat(arq).st_size
            except OSError:
                pass

        self.bytes_processados_total = 0
        self.tempo_inicio_total = time.time()

        palavra_arq_inicio = "arquivo" if total_arquivos == 1 else "arquivos"
        self.texto_saida.append(f"Processando {total_arquivos} {palavra_arq_inicio}...\n")

        # Verifica se Custódia veio de PDF
        veio_de_pdf = False
        if texto_custodia:
            nome_ref = getattr(self.texto_referencia, 'nome_arquivo_origem', None)
            if nome_ref and nome_ref.lower().endswith('.pdf'): veio_de_pdf = True

        # --- INICIA O WORKER ---
        self.worker = WorkerExtracao(
            lista_arquivos, info_drive, texto_custodia, veio_de_pdf,
            algos_selecionados, extrair_meta, extrair_raw, janela=self
        )

        # Conexões Thread-Safe Seguras
        self.worker.sig_texto_append.connect(self.texto_saida.append)
        self.worker.sig_progresso_arquivo.connect(self.barra_arquivo.setValue)
        self.worker.sig_progresso_total.connect(self.barra_total.setValue)
        self.worker.sig_lbl_arquivo.connect(self.lbl_progresso_arquivo.setText)
        self.worker.sig_lbl_total.connect(self.lbl_progresso_total.setText)

        self.worker.sig_sync_bytes.connect(self.sync_bytes_lidos)
        self.worker.sig_apagar_ultima_linha.connect(self.apagar_ultima_linha)
        self.worker.sig_perguntar_nuvem.connect(self.responder_pergunta_nuvem)
        self.worker.sig_conclusao.connect(self.finalizar_processamento)

        self.timer_tempo.start(INTERVALO_ATUALIZACAO_BARRA_PREVISAO_PROGRESSO_TOTAL * 1000)
        self.worker.start()

    def mostrar_alerta_gps(self):
        """Abre uma janela exibindo os links clicáveis para o Google Maps."""
        dialog = QDialog(self)
        dialog.setWindowTitle("📍 Coordenadas GPS Encontradas!")
        dialog.resize(850, 600)

        # --- Força a centralização exata da janela em relação à interface principal ---
        centro_pai = self.geometry().center()
        dialog.move(centro_pai.x() - dialog.width() // 2, centro_pai.y() - dialog.height() // 2)

        layout = QVBoxLayout(dialog)

        # =====================================================================
        from PySide6.QtCore import QObject, QEvent

        class FiltroTooltipCentro(QObject):
            def eventFilter(self, obj, event):
                # Quando o mouse entra no botão
                if event.type() == QEvent.Type.Enter:
                    centro = obj.rect().center()
                    # Desloca levemente para baixo para não tampar o texto do botão
                    centro.setY(centro.y() + 20)
                    pos_global = obj.mapToGlobal(centro)
                    # Força a exibição da tooltip nessa coordenada exata
                    QToolTip.showText(pos_global, obj.toolTip(), obj)
                    return True
                # Bloqueia o delay padrão e a posição da tooltip do sistema operacional
                elif event.type() == QEvent.Type.ToolTip:
                    return True
                    # Apaga a tooltip quando o mouse sai
                elif event.type() == QEvent.Type.Leave:
                    QToolTip.hideText()
                return False
        # =====================================================================

        # Verifica se há algum algoritmo de hash superior ao CRC32 selecionado
        algos_selecionados = [algo for algo, chk in self.chk_hashes.items() if chk.isChecked()]
        tem_hash_forte = any(algo != "CRC32" for algo in algos_selecionados)

        texto_ignorados = " (arquivos idênticos são ignorados)" if tem_hash_forte else ""

        # Conta quantos arquivos únicos possuem coordenadas
        arquivos_unicos = len(set(arquivo for arquivo, lat, lon in self.coordenadas_gps_encontradas))
        total_coordenadas = len(self.coordenadas_gps_encontradas)

        # Define o plural ou singular das palavras
        verbo = "Foi encontrada" if total_coordenadas == 1 else "Foram encontradas"
        str_coord = "coordenada" if total_coordenadas == 1 else "coordenadas"
        str_arq = "arquivo" if arquivos_unicos == 1 else "arquivos"

        lbl_info = QLabel(
            f"{verbo} <b>{total_coordenadas}</b> {str_coord} GPS em <b>{arquivos_unicos}</b> {str_arq} "
            f"nesta extração{texto_ignorados}.<br>Abaixo estão os links individuais gerados (os links também estão no texto da extração):"
        )
        layout.addWidget(lbl_info)

        # Caixa de texto com links individuais HTML
        from PySide6.QtWidgets import QTextBrowser

        texto_links = QTextBrowser()
        texto_links.setReadOnly(True)
        texto_links.setOpenExternalLinks(True)

        html_links = "<ul style='line-height: 1.5;'>"
        for nome, lat, lon in self.coordenadas_gps_encontradas:
            lat_float = float(lat)
            lon_float = float(lon)
            link = f"https://www.google.com/maps/search/?api=1&query={lat_float:.6f},{lon_float:.6f}"
            html_links += f"<li><b>{nome}</b>: <a href='{link}' style='color: #0056b3; text-decoration: none;'>Abrir Localização no Google Maps</a></li>"
        html_links += "</ul>"

        texto_links.setHtml(html_links)
        layout.addWidget(texto_links)

        # Filtra coordenadas únicas mantendo a ordem de aparição para a rota do Google Maps
        pontos_unicos = []
        coords_vistas = set()
        for item in self.coordenadas_gps_encontradas:
            coord = (float(item[1]), float(item[2]))
            if coord not in coords_vistas:
                coords_vistas.add(coord)
                pontos_unicos.append(item)

        # Link com "Todos os pontos"
        if len(pontos_unicos) > 1:
            layout.addSpacing(10)

            # 1. Limita a 10 pontos porque a URL de rotas do Google Maps começa a falhar com excessos
            pontos_limite = pontos_unicos[:10]

            # 2. Calcula o centróide exclusivamente desses pontos selecionados
            centro_lat = sum(float(lat) for _, lat, _ in pontos_limite) / len(pontos_limite)
            centro_lon = sum(float(lon) for _, _, lon in pontos_limite) / len(pontos_limite)

            # 3. Define a lógica de ordenação angular (Arco Tangente)
            def calcular_angulo(item):
                _, lat, lon = item
                return math.atan2(float(lat) - centro_lat, float(lon) - centro_lon)

            # 4. Ordena os pontos formando o perímetro ao redor do centro
            pontos_ordenados = sorted(pontos_limite, key=calcular_angulo)

            # 5. Gera a string de rota usando a nova ordem
            pontos_rota = "/".join([f"{lat},{lon}" for _, lat, lon in pontos_ordenados])

            # URL OFICIAL DO GOOGLE MAPS PARA ROTAS (MÚLTIPLOS PONTOS)
            link_todos = f"https://www.google.com/maps/dir/{pontos_rota}"

            # Formata o aviso de limite separadamente para quebrar linha, se existir
            aviso_limite = "<br><span style='font-size: 9pt;'>(Limitado aos 10 primeiros pontos devido a restrições do Google Maps)</span>" if len(
                pontos_unicos) > 10 else ""

            # Define o texto do botão dinamicamente
            if len(pontos_unicos) < 10:
                texto_botao = f"Mostrar {len(pontos_unicos)} pontos únicos no Google Maps"
            else:
                texto_botao = "Mostrar 10 primeiros pontos únicos no Google Maps"

            # Criação do botão solicitado para abrir o mapa integrado
            btn_mostrar_10_pontos = QPushButton(texto_botao)
            btn_mostrar_10_pontos.setMinimumHeight(35)
            # --- CORES DINÂMICAS: BOTÃO MAPS (AMARELO) ---
            is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
            bg_maps = "#2b2000" if is_dark else "#fff2cc"
            fg_maps = "#ffcc66" if is_dark else "#b27a00"
            bd_maps = "#664d00" if is_dark else "#ffe599"
            hv_maps = "#403000" if is_dark else "#ffe599"
            pr_maps = "#1a1300" if is_dark else "#ffd966"

            btn_mostrar_10_pontos.setStyleSheet(f"""
                                                QPushButton {{
                                                    background-color: {bg_maps}; 
                                                    color: {fg_maps}; 
                                                    font-weight: bold; 
                                                    border: 1px solid {bd_maps}; 
                                                    border-radius: 4px;
                                                }}
                                                QPushButton:hover {{ background-color: {hv_maps}; }}
                                                QPushButton:pressed {{ background-color: {pr_maps}; }}
                                            """)

            # --- MELHORIA DA TOOLTIP (HTML + POSIÇÃO CENTRALIZADA) ---
            # Adicionado width (largura) e font-size (tamanho da fonte)
            tooltip_texto = (
                "<table width='500'><tr><td align='center' style='padding: 5px; font-size: 11pt;'>"
                "Como o Google Maps não permite alfinetes múltiplos por URL,<br>"
                "você pode usar o modo <b>'Rota'</b> para ver os pontos interligados de forma sequencial."
                f"{aviso_limite}"
                "</td></tr></table>"
            )
            btn_mostrar_10_pontos.setToolTip(tooltip_texto)

            # Instancia o filtro e atrela ao botão
            btn_mostrar_10_pontos._filtro_centro = FiltroTooltipCentro(btn_mostrar_10_pontos)
            btn_mostrar_10_pontos.installEventFilter(btn_mostrar_10_pontos._filtro_centro)

            # ---------------------------------------------------------

            # Função interna para chamar o navegador nativo
            def abrir_rota_agrupada():
                import webbrowser
                webbrowser.open(link_todos)

            btn_mostrar_10_pontos.clicked.connect(abrir_rota_agrupada)
            layout.addWidget(btn_mostrar_10_pontos)

        # Botões do Rodapé
        layout.addSpacing(10)
        layout_botoes = QHBoxLayout()

        btn_copiar = QPushButton("Copiar Lista (Ctrl+C) de links Google Maps (todos os pontos encontrados)")
        btn_copiar.setMinimumHeight(35)
        # --- CORES DINÂMICAS: BOTÃO COPIAR (VERDE) ---
        is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()
        bg_copy = "#0d2611" if is_dark else "#e8f5e9"
        fg_copy = "#81c784" if is_dark else "#2e7d32"
        bd_copy = "#1b5e20" if is_dark else "#c8e6c9"
        hv_copy = "#143d1a" if is_dark else "#c8e6c9"
        pr_copy = "#0a1a0c" if is_dark else "#a5d6a7"

        btn_copiar.setStyleSheet(f"""
                            QPushButton {{
                                background-color: {bg_copy}; 
                                color: {fg_copy}; 
                                font-weight: bold; 
                                border: 1px solid {bd_copy}; 
                                border-radius: 4px;
                            }}
                            QPushButton:hover {{ background-color: {hv_copy}; }}
                            QPushButton:pressed {{ background-color: {pr_copy}; }}
                        """)

        # Função interna para formatar a lista simplificada e mandar para a área de transferência
        def copiar_links():
            texto_copia = "=== COORDENADAS GPS EXTRAÍDAS ===\n\n"
            for caminho_completo, lat, lon in self.coordenadas_gps_encontradas:
                lat_float = float(lat)
                lon_float = float(lon)
                link = f"https://www.google.com/maps/search/?api=1&query={lat_float:.6f},{lon_float:.6f}"
                texto_copia += f"Arquivo: {caminho_completo}\nLink: {link}\n\n"

            QApplication.clipboard().setText(texto_copia)
            btn_copiar.setText("Copiado!")

            # Restaura o texto original do botão após 1.5 segundos
            QTimer.singleShot(1500, lambda: btn_copiar.setText("Copiar Lista (Ctrl+C) de links Google Maps (todos os pontos encontrados)"))

        btn_copiar.clicked.connect(copiar_links)

        # --- BOTÃO UNIFICADO KML ---
        btn_exportar_kml_todos = QPushButton("Exportar KML (todos os pontos encontrados)")
        btn_exportar_kml_todos.setMinimumHeight(35)

        # --- TOOLTIP KML COM ESTILO E FILTRO ---
        tooltip_texto_kml = (
            "<table width='350'><tr><td align='center' style='padding: 5px; font-size: 11pt;'>"
            "Para visualização no Google Earth<br>e no Google MyMaps"
            "</td></tr></table>"
        )
        btn_exportar_kml_todos.setToolTip(tooltip_texto_kml)

        # Reutiliza o filtro criado acima para garantir que a tooltip apareça centralizada abaixo do botão
        btn_exportar_kml_todos._filtro_centro = FiltroTooltipCentro(btn_exportar_kml_todos)
        btn_exportar_kml_todos.installEventFilter(btn_exportar_kml_todos._filtro_centro)
        # ----------------------------------------

        # --- CORES DINÂMICAS: BOTÃO KML (AZUL) ---
        bg_kml = "#001a33" if is_dark else "#e6f2ff"
        fg_kml = "#66b2ff" if is_dark else "#005a9e"
        bd_kml = "#003366" if is_dark else "#b3d4ff"
        hv_kml = "#002b5e" if is_dark else "#cce5ff"
        pr_kml = "#001122" if is_dark else "#99ccff"

        btn_exportar_kml_todos.setStyleSheet(f"""
                            QPushButton {{
                                background-color: {bg_kml}; 
                                color: {fg_kml}; 
                                font-weight: bold; 
                                border: 1px solid {bd_kml}; 
                                border-radius: 4px;
                            }}
                            QPushButton:hover {{ background-color: {hv_kml}; }}
                            QPushButton:pressed {{ background-color: {pr_kml}; }}
                        """)
        btn_exportar_kml_todos.clicked.connect(self.abrir_menu_exportacao_kml)

        # Montagem do layout
        layout_botoes.addWidget(btn_copiar)
        layout_botoes.addWidget(btn_exportar_kml_todos)

        layout.addLayout(layout_botoes)

        dialog.exec()

    def abrir_menu_exportacao_kml(self):
        """Abre uma nova janela contendo as opções específicas de exportação KML."""
        dialog_kml = QDialog(self)
        dialog_kml.setWindowTitle("Opções de Exportação KML")
        dialog_kml.setMinimumWidth(380)
        layout = QVBoxLayout(dialog_kml)

        lbl_info = QLabel("Selecione o formato desejado para a exportação:")
        lbl_info.setStyleSheet("margin-bottom: 10px;")
        layout.addWidget(lbl_info)

        # --- VERIFICAÇÃO DE MODO ESCURO ---
        is_dark = hasattr(self, "chk_modo_escuro") and self.chk_modo_escuro.isChecked()

        # --- BOTÃO KML (PONTOS) - AZUL ---
        bg_pt = "#001a33" if is_dark else "#e6f2ff"
        fg_pt = "#66b2ff" if is_dark else "#005a9e"
        bd_pt = "#003366" if is_dark else "#b3d4ff"
        hv_pt = "#002b5e" if is_dark else "#cce5ff"
        pr_pt = "#001122" if is_dark else "#99ccff"

        btn_kml_pontos = QPushButton("📍 Exportar KML (Pontos)")
        btn_kml_pontos.setMinimumHeight(35)
        btn_kml_pontos.setStyleSheet(f"""
                            QPushButton {{
                                background-color: {bg_pt}; 
                                color: {fg_pt}; 
                                font-weight: bold; 
                                border: 1px solid {bd_pt}; 
                                border-radius: 4px;
                            }}
                            QPushButton:hover {{ background-color: {hv_pt}; }}
                            QPushButton:pressed {{ background-color: {pr_pt}; }}
                        """)
        btn_kml_pontos.clicked.connect(self.exportar_kml_pontos)

        # --- BOTÃO KML (POLÍGONO) - VERMELHO ---
        bg_pl = "#330000" if is_dark else "#ffe6e6"
        fg_pl = "#ff6666" if is_dark else "#990000"
        bd_pl = "#660000" if is_dark else "#ffb3b3"
        hv_pl = "#4d0000" if is_dark else "#ffcccc"
        pr_pl = "#1a0000" if is_dark else "#ff9999"

        # Cores para o estado desativado (disabled)
        bg_dis = "#2b2b2b" if is_dark else "#e0e0e0"
        fg_dis = "#666666" if is_dark else "#888888"
        bd_dis = "#444444" if is_dark else "#cccccc"

        btn_kml_poligono = QPushButton("🛑 Exportar KML (Polígono)")
        btn_kml_poligono.setMinimumHeight(35)
        btn_kml_poligono.setStyleSheet(f"""
                            QPushButton {{
                                background-color: {bg_pl}; 
                                color: {fg_pl}; 
                                font-weight: bold; 
                                border: 1px solid {bd_pl}; 
                                border-radius: 4px;
                            }}
                            QPushButton:hover {{ background-color: {hv_pl}; }}
                            QPushButton:pressed {{ background-color: {pr_pl}; }}
                            QPushButton:disabled {{
                                background-color: {bg_dis}; 
                                color: {fg_dis}; 
                                border: 1px solid {bd_dis}; 
                                font-weight: normal;
                            }}
                        """)
        btn_kml_poligono.clicked.connect(self.exportar_kml_poligono)

        # Lógica de desativação do polígono (considerando apenas coordenadas únicas)
        coordenadas_unicas = set((lat, lon) for _, lat, lon in self.coordenadas_gps_encontradas)
        if len(coordenadas_unicas) < 3:
            btn_kml_poligono.setEnabled(False)
            btn_kml_poligono.setToolTip("Necessário no mínimo 3 coordenadas distintas para desenhar um polígono.")

        # --- BOTÃO INSTRUÇÕES (CINZA/NEUTRO) ---
        bg_inst = "#3c3f41" if is_dark else "#f0f0f0"
        fg_inst = "#f0f0f0" if is_dark else "#000000"
        bd_inst = "#555555" if is_dark else "#cccccc"
        hv_inst = "#4b4d4f" if is_dark else "#e0e0e0"
        pr_inst = "#2b2b2b" if is_dark else "#d0d0d0"

        btn_instrucoes = QPushButton("Instruções para visualizar arquivos KML")
        btn_instrucoes.setMinimumHeight(35)
        btn_instrucoes.setStyleSheet(f"""
                            QPushButton {{
                                font-weight: bold;
                                background-color: {bg_inst};
                                color: {fg_inst};
                                border: 1px solid {bd_inst};
                                border-radius: 4px;
                            }}
                            QPushButton:hover {{ background-color: {hv_inst}; }}
                            QPushButton:pressed {{ background-color: {pr_inst}; }}
                        """)
        btn_instrucoes.clicked.connect(self.mostrar_instrucoes_kml)

        # Adiciona botões ao layout
        layout.addWidget(btn_kml_pontos)
        layout.addWidget(btn_kml_poligono)
        layout.addWidget(btn_instrucoes)

        # Botão Fechar padrão
        layout.addSpacing(10)
        btn_fechar = QPushButton("Fechar")
        btn_fechar.clicked.connect(dialog_kml.accept)
        layout.addWidget(btn_fechar)

        dialog_kml.exec()

    def mostrar_instrucoes_kml(self):
        """Exibe as instruções sobre como abrir os arquivos KML no Google Earth/Maps."""
        msg = QMessageBox(self)
        msg.setWindowTitle("Como visualizar arquivos KML?")

        # Habilita a interação com a caixa de texto para que os links sejam clicáveis
        msg.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)

        msg.setText(
            "<div style='font-size: 11pt; line-height: 1.4;'>"
            "<h3 style='margin-bottom: 5px;'>Opção 1: Google Earth Web (Recomendado)</h3>"
            "<p style='margin-top: 0;'>1. Acesse <a href='https://earth.google.com/web' style='color: #0056b3; text-decoration: none;'><b>earth.google.com/web</b></a> no seu navegador.<br>"
            "2. No menu lateral, clique em <b>Projetos</b> (ícone de alfinete sobre um quadrado).<br>"
            "3. Clique no botão <b>Novo</b> e depois em <b>Importar arquivo para o projeto do mapa</b>.</p>"
            "<hr>"
            "<h3 style='margin-bottom: 5px;'>Opção 2: Google Maps (My Maps)</h3>"
            "<p style='margin-top: 0;'>1. Acesse o <a href='www.google.com/maps/d/' style='color: #0056b3; text-decoration: none;'><b>Google My Maps</b></a> (logado na sua conta Google).<br>"
            "2. Clique no botão vermelho <b>Criar um novo mapa</b>.<br>"
            "3. Na caixa flutuante do lado esquerdo, clique no link <b>Importar</b> e selecione o arquivo gerado.</p>"
            "</div>"
        )
        msg.exec()

    def exportar_kml_pontos(self):
        if not self.coordenadas_gps_encontradas:
            return

        # 1. CHAMA A NOVA JANELA DE METADADOS
        dialogo = DialogoMetadadosKML(self)
        if dialogo.exec() != QDialog.DialogCode.Accepted:
            return  # Usuário fechou ou clicou em Cancelar

        import html
        dados_kml_sujos = dialogo.obter_dados()

        # Higieniza os dados digitados pelo usuário para não corromper o XML do KML
        dados_kml = {k: html.escape(str(v)) if v is not None else None for k, v in dados_kml_sujos.items()}

        # 2. SEGUIMENTO NORMAL (Escolher onde salvar)
        opcoes_salvar = QFileDialog.Option.DontUseNativeDialog
        caminho_salvar, _ = QFileDialog.getSaveFileName(
            self,
            "Salvar Mapa de Pontos de Evidência",
            "mapa_evidencias_pontos.kml",
            "Google Earth KML (*.kml)",
            options=opcoes_salvar
        )

        if not caminho_salvar:
            return

        # Formatação segura para o My Maps (Bullet points em linha única para não grudar)
        nome_doc = f"Pontos - {dados_kml['caso']} ({dados_kml['laudo']})"
        desc_doc = f"Laudo: {dados_kml['laudo']} • Operação: {dados_kml['caso']} • Usuário: {dados_kml['perito']} • Descrição: {dados_kml['descricao']}"

        # Usa o texto do usuário se houver, senão aplica o genérico
        desc_usuario = dados_kml['descricao']
        desc_placemark = desc_usuario if desc_usuario != "Sem descrição adicional." else "Ponto de interesse extraído dos metadados."

        # Cabeçalho padrão obrigatório do KML (Minificado)
        kml_content = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<kml xmlns="http://www.opengis.net/kml/2.2" xmlns:gx="http://www.google.com/kml/ext/2.2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.opengis.net/kml/2.2 https://developers.google.com/kml/schema/kml22gx.xsd">',
            f'<Document><name>{nome_doc}</name><description>{desc_doc}</description>'
        ]

        # Cria um alfinete (Placemark) para cada arquivo, usando ExtendedData para criar uma tabela nativa
        for caminho_completo, lat, lon in self.coordenadas_gps_encontradas:
            nome_arquivo = os.path.basename(caminho_completo)
            lat_float = float(lat)
            lon_float = float(lon)

            # Injeta a variável {desc_placemark} dinamicamente na tag <description>
            kml_content.append(
                f'<Placemark><name>{nome_arquivo}</name><description>{desc_placemark}</description><ExtendedData><Data name="Caminho Original"><value>{caminho_completo}</value></Data></ExtendedData><Point><coordinates>{lon_float:.6f},{lat_float:.6f}</coordinates></Point></Placemark>')

        kml_content.append('</Document></kml>')

        try:
            with open(caminho_salvar, 'w', encoding='utf-8') as f:
                # Junta tudo sem quebras de linha
                f.write("".join(kml_content))
            QMessageBox.information(self, "Sucesso", "Arquivo KML de pontos gerado com sucesso!")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Ocorreu um erro ao salvar o KML:\n{e}")

    def exportar_kml_poligono(self):
        # Extrai apenas as coordenadas únicas logo de cara
        pontos = list(set((float(lat), float(lon)) for _, lat, lon in self.coordenadas_gps_encontradas))

        if len(pontos) < 3:
            QMessageBox.warning(self, "Aviso", "São necessários pelo menos 3 pontos distintos para formar um polígono.")
            return

        # 1. CHAMA A NOVA JANELA DE METADADOS
        dialogo = DialogoMetadadosKML(self)
        if dialogo.exec() != QDialog.DialogCode.Accepted:
            return

        dados_kml = dialogo.obter_dados()

        # 2. SEGUIMENTO NORMAL
        opcoes_salvar = QFileDialog.Option.DontUseNativeDialog
        caminho_salvar, _ = QFileDialog.getSaveFileName(
            self,
            "Salvar Polígono de Área Periciada",
            "mapa_evidencias_poligono.kml",
            "Google Earth KML (*.kml)",
            options=opcoes_salvar
        )

        if not caminho_salvar:
            return

        # =========================================================
        # INTELIGÊNCIA ESPACIAL: ORDENAÇÃO ANGULAR PARA PERÍMETRO
        # =========================================================
        # A lista 'pontos' já foi criada e filtrada no início da função

        centro_lat = sum(p[0] for p in pontos) / len(pontos)
        centro_lon = sum(p[1] for p in pontos) / len(pontos)

        def calcular_angulo(ponto):
            import math
            return math.atan2(ponto[0] - centro_lat, ponto[1] - centro_lon)

        pontos_ordenados = sorted(pontos, key=calcular_angulo)
        # =========================================================

        # Formatação segura para a pasta Document
        nome_doc = f"Polígono - {dados_kml['caso']} ({dados_kml['laudo']})"
        desc_doc = f"Laudo: {dados_kml['laudo']} • Operação: {dados_kml['caso']} • Usuário: {dados_kml['perito']} • Descrição: {dados_kml['descricao']}"

        # Usa o texto do usuário se houver, senão aplica o genérico
        desc_usuario = dados_kml['descricao']
        desc_placemark = desc_usuario if desc_usuario != "Sem descrição adicional." else "Perímetro geográfico da área periciada."

        # Estrutura base do KML com ExtendedData gerando uma TABELA NATIVA
        kml_content = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<kml xmlns="http://www.opengis.net/kml/2.2" xmlns:gx="http://www.google.com/kml/ext/2.2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.opengis.net/kml/2.2 https://developers.google.com/kml/schema/kml22gx.xsd">',
            f'<Document><name>{nome_doc}</name><description>{desc_doc}</description>',
            f'<Placemark><name>Área Mapeada</name><description>{desc_placemark}</description>',
            '<ExtendedData>',
            f'<Data name="Laudo"><value>{dados_kml["laudo"]}</value></Data>',
            f'<Data name="Operação"><value>{dados_kml["caso"]}</value></Data>',
            f'<Data name="Usuário"><value>{dados_kml["perito"]}</value></Data>',
            '</ExtendedData>',
            '<Polygon><outerBoundaryIs><LinearRing><coordinates>'
        ]

        lista_coordenadas_kml = []
        for lat, lon in pontos_ordenados:
            lista_coordenadas_kml.append(f"{lon:.6f},{lat:.6f}")

        primeiro_ponto = lista_coordenadas_kml[0]
        lista_coordenadas_kml.append(primeiro_ponto)

        # O espaço simples entre as coordenadas é exigido pelo padrão KML
        linha_coordenadas = " ".join(lista_coordenadas_kml)
        kml_content.append(linha_coordenadas)

        kml_content.append('</coordinates></LinearRing></outerBoundaryIs></Polygon></Placemark></Document></kml>')

        try:
            with open(caminho_salvar, 'w', encoding='utf-8') as f:
                # Junta tudo sem quebras de linha
                f.write("".join(kml_content))
            QMessageBox.information(self, "Sucesso", "Arquivo KML de polígono gerado com perímetro organizado!")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Ocorreu um erro ao salvar o KML:\n{e}")

    def sync_bytes_lidos(self, valor):
        self.bytes_processados_total = valor

    def apagar_ultima_linha(self):
        """Apaga visualmente a linha de renderização pesada para não poluir a tela."""
        if not self._limite_tela_atingido:
            cursor = self.texto_saida.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            cursor.select(QTextCursor.SelectionType.BlockUnderCursor)
            cursor.removeSelectedText()
            cursor.deletePreviousChar()
            self.texto_saida.setTextCursor(cursor)
        if self._relatorio_memoria and "Renderizando Raw Dump" in self._relatorio_memoria[-1]:
            self._relatorio_memoria.pop()

    def responder_pergunta_nuvem(self, payload):
        """Abre a caixa de diálogo na Main Thread travando a extração com segurança."""
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(payload["titulo"])
        msg_box.setText(payload["texto"])
        msg_box.setInformativeText(payload["info"])
        msg_box.setIcon(QMessageBox.Icon.Warning)

        btn_sim = msg_box.addButton("Sim, ignorar proteção e forçar extração", QMessageBox.ButtonRole.AcceptRole)
        btn_nao = msg_box.addButton("Não, manter bloqueio pericial seguro", QMessageBox.ButtonRole.RejectRole)
        msg_box.exec()

        self.worker.nuvem_resposta = (msg_box.clickedButton() == btn_sim)
        self.worker.nuvem_event.set()  # Libera a Thread do Worker para continuar

    def finalizar_processamento(self, payload):
        """Slot chamado automaticamente quando o Worker conclui o laço for principal."""
        cancelado = payload.get("cancelar_operacao", False)
        self.coordenadas_gps_encontradas = payload.get("coordenadas_gps_encontradas", [])

        legenda_fps_tela = ""
        if self.video_teve_fps_geral:
            legenda_fps_tela += "\n=== NOTAS SOBRE TAXA DE QUADROS (FPS) ===\n- FPS Média/Base: É o número de quadros por segundo informado pelo reprodutor/cabeçalho oficial do arquivo.\n- FPS Calculado (Frames/Duração): É a média matemática exata obtida ao dividir o número total de quadros pela duração do vídeo.\n"
        if self.video_teve_fps_min_max:
            legenda_fps_tela += "- FPS Mínimo: Indica o menor número de quadros registrados em um segundo (comum em vídeos VFR).\n- FPS Máximo: Indica o maior número de quadros registrados em um segundo (a câmera acelerou a captura).\n"

        if legenda_fps_tela:
            self.texto_saida.append(legenda_fps_tela)

        self.btn_copiar.setEnabled(True)
        self.btn_salvar.setEnabled(True)

        self.texto_saida.append("Resumo do conteúdo:")
        contagem_extensoes = payload.get("contagem_extensoes", {})
        extensoes_ordenadas = sorted(contagem_extensoes.items(), key=lambda item: item[1], reverse=True)
        for ext, qtd in extensoes_ordenadas:
            palavra_arq_ext = "arquivo" if qtd == 1 else "arquivos"
            self.texto_saida.append(f"{qtd} {palavra_arq_ext} {ext}")

        arquivos_processados_qtd = payload.get("arquivos_processados_qtd", 0)
        palavra_arq_total = "arquivo" if arquivos_processados_qtd == 1 else "arquivos"
        self.texto_saida.append(
            f"Total de arquivos processados: {arquivos_processados_qtd} {palavra_arq_total}\n")

        # Arquivos Duplicados
        arquivos_por_hash = payload.get("arquivos_por_hash", {})
        if arquivos_processados_qtd > 1:
            self.texto_saida.append(
                "Arquivos idênticos entre si (CRC32 ignorado na comparação se houver outro hash forte):")
            tem_duplicados = False
            for chave_hash, lista_caminhos in arquivos_por_hash.items():
                if len(lista_caminhos) > 1 and chave_hash:
                    tem_duplicados = True
                    algoritmos_coincidentes = " + ".join([item[0] for item in chave_hash])
                    algo_principal, valor_principal = chave_hash[-1]
                    nome_hash = f"Idênticos em {algoritmos_coincidentes} ({algo_principal}: {valor_principal})"
                    self.texto_saida.append(f"\n  [Grupo idêntico - {nome_hash}]")
                    for caminho_dup in lista_caminhos:
                        self.texto_saida.append(f"  ↳ {caminho_dup}")

            if not tem_duplicados: self.texto_saida.append("\n  ↳ não foram encontrados arquivos idênticos entre si")
            self.texto_saida.append("\n" + "-" * 60)

        # Resumo Cadeia de Custódia
        lista_referencia = payload.get("lista_referencia")
        if lista_referencia is not None:
            nome_ref = self.texto_referencia.nome_arquivo_origem
            hash_ref = getattr(self.texto_referencia, 'hash_arquivo_origem', None)

            if nome_ref and hash_ref:
                self.texto_saida.append(
                    f"\n=== RELAÇÃO ORIGINAL DE HASHES (Extraída de: {nome_ref} - SHA-256: {hash_ref}) ===")
            elif nome_ref:
                self.texto_saida.append(f"\n=== RELAÇÃO ORIGINAL DE HASHES (Extraída de: {nome_ref}) ===")
            else:
                self.texto_saida.append("\n=== RELAÇÃO ORIGINAL DE HASHES (CADEIA DE CUSTÓDIA) ===")

            for item in lista_referencia:
                self.texto_saida.append(item)

            self.texto_saida.append("\n" + "-" * 60)
            self.texto_saida.append("\n=== RESUMO DA VALIDAÇÃO DE CUSTÓDIA ===")
            self.texto_saida.append(
                f"✅ Arquivos validados com sucesso (Integridade mantida): {payload.get('qtd_validados', 0)}")
            if payload.get("qtd_alertas_parciais", 0) > 0:
                self.texto_saida.append(
                    f"⚠️ Arquivos com alerta parcial (algum hash com divergência): {payload.get('qtd_alertas_parciais', 0)}")
            self.texto_saida.append(
                f"❌ Arquivos não validados (Hash divergente ou não encontrados): {payload.get('qtd_nao_validados', 0)}")
            self.texto_saida.append("-" * 60)

        # Finalização de Tempo
        self.timer_tempo.stop()
        if not cancelado:
            tempo_total = time.time() - self.tempo_inicio_total
            horas, resto = divmod(tempo_total, 3600)
            minutos, segundos = divmod(resto, 60)
            h, m, s = int(horas), int(minutos), int(segundos)

            if h > 0:
                str_tempo_final = f"{h}h{m}min{s}s"
            elif m > 0:
                str_tempo_final = f"{m}min{s}s"
            else:
                str_tempo_final = f"{s}s" if s > 0 else "&lt; 1s"

            self.lbl_progresso_arquivo.setText("Progresso do Arquivo Atual: Concluído!")
            self.lbl_progresso_total.setText(
                f"Progresso Total (Arquivos) - Concluído! (Tempo Decorrido: {str_tempo_final})")
            self.texto_saida.append(f"Processamento concluído com sucesso em {str_tempo_final}!\n")
        else:
            self.lbl_progresso_total.setText("Progresso Total (Arquivos) - Cancelado pelo usuário.")

        self.btn_cancelar.setEnabled(False)
        self.btn_cancelar.setText("CANCELAR PROCESSAMENTO")

        scrollbar = self.texto_saida.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

        self.destravar_interface()

        if self.coordenadas_gps_encontradas:
            self.mostrar_alerta_gps()


class DialogoMetadadosKML(QDialog):
    def __init__(self, parent=None, texto_botao="Continuar e Salvar KML", modo_e01=False):
        super().__init__(parent)
        self.setWindowTitle("Identificação Forense do KML")
        self.setMinimumWidth(450)
        self.modo_e01 = modo_e01

        layout = QVBoxLayout(self)

        # Texto instrutivo
        lbl_info = QLabel(
            "Preencha os dados forenses abaixo para a identificação do arquivo gerado.<br><i>(Deixe em branco o que não quiser preencher)</i>")
        layout.addWidget(lbl_info)
        layout.addSpacing(10)

        # Campos de entrada
        self.inp_caso = QLineEdit()
        self.inp_caso.setMaxLength(255)
        self.inp_caso.setPlaceholderText("Ex: Operação X / Inquérito 123/2026 (Máx: 255 caracteres)")
        self.inp_caso.setToolTip("Limite de segurança: 255 caracteres.")

        self.inp_laudo = QLineEdit()
        self.inp_laudo.setMaxLength(255)
        self.inp_laudo.setPlaceholderText("Ex: Laudo Pericial nº 4567/2026 (Máx: 255 caracteres)")
        self.inp_laudo.setToolTip("Limite de segurança: 255 caracteres.")

        self.inp_perito = QLineEdit()
        self.inp_perito.setMaxLength(255)
        self.inp_perito.setPlaceholderText("Ex: Perito Criminal Fulano de Tal (Máx: 255 caracteres)")
        self.inp_perito.setToolTip("Limite de segurança: 255 caracteres.")

        self.inp_desc = QTextEdit()
        self.inp_desc.setMaximumHeight(80)
        self.inp_desc.setPlaceholderText("Descrição adicional ou observações relevantes... (Máx: 1500 caracteres)")

        # Ajusta dinamicamente a informação do Tooltip
        desc_tooltip = "Limite de segurança: 1500 caracteres."
        if self.modo_e01:
            desc_tooltip += " Quebras de linha serão convertidas em traços no E01 final."
        self.inp_desc.setToolTip(desc_tooltip)

        # --- Combo box para definir o limite de fragmentação do E01 ---
        self.combo_split = QComboBox()
        self.combo_split.setStyleSheet("padding: 4px; font-size: 10pt;")
        # O segundo valor é o argumento exato que vai pro ewfacquire
        self.combo_split.addItem("Padrão (1.4 GB) - ewfacquire nativo", "")
        self.combo_split.addItem("640 MB (Tamanho de CD)", "640M")
        self.combo_split.addItem("4.3 GB (Tamanho de DVD)", "4.3G")
        self.combo_split.addItem("1 GB", "1G")
        self.combo_split.addItem("2 GB", "2G")
        self.combo_split.addItem("4 GB (Compatível com discos FAT32)", "4G")
        self.combo_split.addItem("8 GB", "8G")
        self.combo_split.addItem("16 GB", "16G")
        self.combo_split.addItem("Arquivo Único (Não dividir)", "7.9E")

        self.chk_validacao = QCheckBox("Fazer validação criptográfica automática pós-extração")
        self.chk_validacao.setChecked(True)
        self.chk_validacao.setStyleSheet("font-size: 10pt; font-weight: bold; margin-top: 10px;")

        # Adicionando os campos ao layout com rótulos
        layout.addWidget(QLabel("<b>Nome da Operação / Caso:</b>"))
        layout.addWidget(self.inp_caso)

        layout.addWidget(QLabel("<b>Número do Laudo / Procedimento:</b>"))
        layout.addWidget(self.inp_laudo)

        layout.addWidget(QLabel("<b>Nome do Perito / Analista:</b>"))
        layout.addWidget(self.inp_perito)

        # Adiciona o seletor de tamanho apenas se for o modo E01
        if self.modo_e01:
            layout.addWidget(QLabel("<b>Tamanho Máximo da Imagem (Fragmentação):</b>"))
            layout.addWidget(self.combo_split)

        layout.addWidget(QLabel("<b>Descrição (Opcional):</b>"))
        layout.addWidget(self.inp_desc)

        # Adiciona a checagem de validação apenas se for o modo E01
        if self.modo_e01:
            layout.addWidget(self.chk_validacao)

        layout.addSpacing(15)

        # Botões de Ação
        btn_layout = QHBoxLayout()
        btn_ok = QPushButton(texto_botao)
        # Adicionado efeito hover (muda para um cinza ligeiramente mais escuro ao passar o mouse)
        btn_ok.setStyleSheet("""
            QPushButton {
                font-weight: bold; 
                background-color: #e0e0e0; 
                color: #111111;
                border: 1px solid #b5b5b5;
                border-radius: 4px;
                padding: 4px;
            }
            QPushButton:hover {
                background-color: #d4d4d4;
            }
            QPushButton:pressed {
                background-color: #c5c5c5;
            }
        """)
        btn_cancelar = QPushButton("Cancelar")

        btn_ok.clicked.connect(self.accept)
        btn_cancelar.clicked.connect(self.reject)

        btn_layout.addStretch()
        btn_layout.addWidget(btn_ok)
        btn_layout.addWidget(btn_cancelar)

        layout.addLayout(btn_layout)

    def obter_dados(self):
        """Retorna um dicionário com os dados preenchidos ou 'Não informado'."""
        return {
            "caso": self.inp_caso.text().strip() or "Não informado",
            "laudo": self.inp_laudo.text().strip() or "Não informado",
            "perito": self.inp_perito.text().strip() or "Não informado",
            "descricao": self.inp_desc.toPlainText().strip() or "Sem descrição adicional.",
            "split": self.combo_split.currentData() if self.modo_e01 else None,
            "fazer_validacao": self.chk_validacao.isChecked() if self.modo_e01 else True
        }


if __name__ == "__main__":
    def manipulador_excecoes_global(exc_type, exc_value, exc_traceback):
        # 1. Formata as datas (uma para o texto interno, outra segura para o nome do arquivo)
        agora = datetime.datetime.now()
        str_data_hora = agora.strftime("%d/%m/%Y %H:%M:%S")
        str_arquivo_data = agora.strftime("%Y%m%d_%H%M%S")

        # 2. Define o nome dinâmico do arquivo de log
        nome_arquivo = f"crash_log_{str_arquivo_data}.txt"
        caminho_log = BASE_DIR / nome_arquivo

        # 3. Extrai a trilha completa do erro
        log_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))

        # 4. Monta o texto amigável e instrutivo do log
        texto_log = (
            f"=== RELATÓRIO DE ERRO CRÍTICO ({NOME_APP}) ===\n"
            f"Data e Hora: {str_data_hora}\n"
            f"Versão do Programa: {VERSAO_APP}\n"
            f"--------------------------------------------------\n"
            f"ATENÇÃO:\n"
            f"O programa encontrou um erro inesperado e precisou ser encerrado.\n\n"
            f"Por favor, ajude a corrigir este problema enviando ESTE ARQUIVO\n"
            f"({nome_arquivo}) como anexo para o desenvolvedor no e-mail:\n\n"
            f"-> {EMAIL_CONTATO} <-\n\n"
            f"Faça um breve relato do que ocorreu.\n"
            f"--------------------------------------------------\n\n"
            f"DETALHES TÉCNICOS DO ERRO (Traceback):\n"
            f"{log_msg}\n"
        )

        # 5. Salva o arquivo fisicamente (usamos 'w' para criar um arquivo novo e limpo por crash)
        try:
            with open(caminho_log, "w", encoding="utf-8") as f:
                f.write(texto_log)
        except Exception:
            pass  # Se o próprio sistema de log falhar por falta de permissão, ignoramos para não criar um loop de erros

        # 6. Exibe a caixa de aviso na interface ANTES de fechar o programa
        # Verifica se a QApplication ainda está rodando para podermos desenhar a janela
        app_instancia = QApplication.instance()
        if app_instancia:
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Icon.Critical)
            msg_box.setWindowTitle("Erro Crítico Inesperado")
            msg_box.setText("Ocorreu um erro fatal e o extrator precisará ser encerrado.")
            msg_box.setInformativeText(
                f"Um relatório de erro foi salvo automaticamente em:<br>"
                f"<b>{caminho_log}</b><br><br>"
                f"Por favor, envie este arquivo gerado para o e-mail:<br>"
                f"<b>{EMAIL_CONTATO}</b><br>"
                f"com um breve relato do que ocorreu.<br><br>"
                f"Isso ajudará a investigar e corrigir o problema nas próximas versões."
            )
            msg_box.exec()

        # 7. Dispara o comportamento padrão do sistema para finalizar o fechamento
        sys.__excepthook__(exc_type, exc_value, exc_traceback)


    # Injeta a função manipulador_excecoes_global como o "para-quedas" oficial do Python para exceções não tratadas
    sys.excepthook = manipulador_excecoes_global

    # Se for modo helper (elevado), roda e sai antes de subir GUI
    try:
        if "--raw-hash" in sys.argv:
            raise SystemExit(cli_raw_mode_main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception:
        # se falhar no helper, ainda tentamos subir GUI (ou você pode abortar)
        pass

    # Inicialização normal da interface
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # --- ESTILO GLOBAL PARA TOOLTIPS ---
    app.setStyleSheet("""
            QToolTip {
                background-color: #ffffff;
                color: #000000;
                border: 1px solid #cccccc;
                padding: 2px;
                font-size: 10pt;
            }
        """)
    # -----------------------------------------

    if os.path.exists(ICON_PATH):
        app.setWindowIcon(QIcon(ICON_PATH))

    janela = JanelaHashes()
    janela.showMaximized()
    sys.exit(app.exec())