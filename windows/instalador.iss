; Instalador do Limpa Cookies para Windows 10 e 11 (Inno Setup 6).
; Chamado por gerar_exe.bat depois de criar dist\LimpaCookies.exe:
;     ISCC /DVersao=1.1.0 windows\instalador.iss
; Instala só para o usuário atual, sem pedir senha de administrador.

#ifndef Versao
  #define Versao "0.0.0"
#endif

[Setup]
AppId={{59F79EA2-21DC-4F5D-9921-5C752BDEE8A7}
AppName=Limpa Cookies
AppVersion={#Versao}
AppPublisher=Limpa Cookies
DefaultDirName={autopf}\Limpa Cookies
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
MinVersion=10.0
OutputDir=..\dist
; nome sem a versao: o link releases/latest/download/LimpaCookies-Instalador.exe
; do README leva sempre ao instalador mais novo
OutputBaseFilename=LimpaCookies-Instalador
SetupIconFile=icone.ico
UninstallDisplayIcon={app}\LimpaCookies.exe
UninstallDisplayName=Limpa Cookies
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "pt"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\LimpaCookies.exe"; DestDir: "{app}"; Flags: ignoreversion

[Registry]
; "Iniciar com o sistema" é ligado pelo próprio programa (aba Configurações);
; aqui só se garante que desinstalar tira o programa do início de sessão.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "LimpaCookiesJanela"; Flags: dontcreatekey uninsdeletevalue

[Icons]
Name: "{autoprograms}\Limpa Cookies"; Filename: "{app}\LimpaCookies.exe"; Comment: "Verifica e elimina os cookies guardados pelos navegadores"
Name: "{autodesktop}\Limpa Cookies"; Filename: "{app}\LimpaCookies.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\LimpaCookies.exe"; Description: "{cm:LaunchProgram,Limpa Cookies}"; Flags: nowait postinstall skipifsilent
