@echo off
rem Gera a versao do Limpa Cookies para Windows 10 e 11.
rem
rem   dist\LimpaCookies.exe                        programa completo num arquivo so (portatil)
rem   dist\LimpaCookies-<versao>-Instalador.exe    instalador com atalho no menu Iniciar;
rem                                                so e criado se houver Inno Setup 6
rem
rem Precisa, apenas no PC onde se gera (nao nos PCs onde o programa vai rodar):
rem   - Python 3.9 ou mais novo, de https://www.python.org/downloads/windows/
rem   - opcional: Inno Setup 6, de https://jrsoftware.org/isdl.php
rem
rem Uso: copie a pasta do projeto para o Windows e de dois cliques neste arquivo.
rem (Sem acentos de proposito: o cmd le arquivos .bat na pagina de codigo antiga.)
setlocal
cd /d "%~dp0.."

set "PY=python"
where py >nul 2>nul && set "PY=py -3"
%PY% -c "import sys, tkinter; sys.exit(sys.version_info < (3, 9))" 2>nul || goto :sem_python

echo [1/3] Preparando o ambiente (baixa o PyInstaller na primeira vez)...
%PY% -m venv build\venv || goto :erro
build\venv\Scripts\python -m pip install --quiet --disable-pip-version-check pyinstaller || goto :erro
set "VERSAO="
for /f "delims=" %%v in ('build\venv\Scripts\python -c "import limpa_cookies; print(limpa_cookies.APP_VERSION)"') do set "VERSAO=%%v"
if not defined VERSAO goto :erro

echo [2/3] Gerando dist\LimpaCookies.exe (versao %VERSAO%)...
build\venv\Scripts\pyinstaller --noconfirm --clean --log-level WARN --onefile --windowed ^
    --name LimpaCookies --icon "%CD%\windows\icone.ico" ^
    --add-data "%CD%\windows\icone.ico;." --exclude-module gi ^
    --distpath dist --workpath build\pyinstaller --specpath build ^
    limpa_cookies.py || goto :erro

set "ISCC="
where ISCC >nul 2>nul && set "ISCC=ISCC"
if not defined ISCC if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%LocalAppData%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LocalAppData%\Programs\Inno Setup 6\ISCC.exe"
if not defined ISCC goto :sem_inno

echo [3/3] Gerando o instalador...
"%ISCC%" /Qp "/DVersao=%VERSAO%" windows\instalador.iss || goto :erro
echo.
echo Pronto:
echo   dist\LimpaCookies.exe
echo   dist\LimpaCookies-%VERSAO%-Instalador.exe
goto :fim

:sem_inno
echo [3/3] Inno Setup 6 nao encontrado: o instalador nao foi gerado.
echo       Instale de https://jrsoftware.org/isdl.php e rode de novo, se quiser o instalador.
echo.
echo Pronto: dist\LimpaCookies.exe (portatil, basta copiar e abrir)
goto :fim

:sem_python
echo Nao encontrei Python 3.9 ou mais novo com Tk.
echo Instale de https://www.python.org/downloads/windows/ e rode de novo.
goto :falhou

:erro
echo.
echo Algo falhou; veja as mensagens acima.

:falhou
pause
exit /b 1

:fim
pause
exit /b 0
