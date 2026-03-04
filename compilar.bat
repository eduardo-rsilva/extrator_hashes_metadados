@echo off
echo ===========================================
echo ATIVANDO COMPILADOR MSVC E AMBIENTE VIRTUAL
echo ===========================================

REM 1. Carrega as variaveis do compilador MSVC na mesma sessao
call "D:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat"

REM 2. Navega e ativa o ambiente virtual do Python 3.12
call "..\..\PyCharm_venvs\extrator_hashes_metadados_estavel\Scripts\activate.bat"

REM 3. Inicia a compilacao usando o Nuitka no mesmo terminal
echo Iniciando build.py...
python build.py

echo.
echo Compilacao finalizada!
pause
