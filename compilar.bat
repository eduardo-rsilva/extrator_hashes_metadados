@echo off
echo ===========================================
echo ATIVANDO COMPILADOR MSVC E AMBIENTE VIRTUAL
echo ===========================================

REM 1. Define o caminho exato do Python ancorado na pasta do script BAT
set VENV_PYTHON="%~dp0..\..\PyCharm_venvs\extrator_hashes_metadados_estavel\Scripts\python.exe"

REM 2. Navega e ativa o ambiente virtual do Python 3.12
call "..\..\PyCharm_venvs\extrator_hashes_metadados_estavel\Scripts\activate.bat"

REM 3. Inicia a compilacao usando o Nuitka no mesmo terminal
echo Iniciando build.py...
python build.py

echo.
echo Compilacao finalizada!
pause
