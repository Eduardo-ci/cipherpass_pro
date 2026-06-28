[Setup]
; Información de la Aplicación
AppName=CipherPass
AppVersion=1.0.4
AppPublisher=Eduardo
AppPublisherURL=https://github.com/Eduardo-ci/Cipherpass_Pro
AppSupportURL=https://github.com/Eduardo-ci/Cipherpass_Pro/issues
AppUpdatesURL=https://github.com/Eduardo-ci/Cipherpass_Pro/releases

; Configuración por defecto de instalación
DefaultDirName={autopf}\CipherPass
DefaultGroupName=CipherPass

; Iconos e interfaz
SetupIconFile=resources\icons\cipherpass.ico
UninstallDisplayIcon={app}\cipherpass.exe

; Configuración de salida
OutputDir=dist
OutputBaseFilename=CipherPass_Setup
Compression=lzma2
SolidCompression=yes

; Permisos (Privilegios mínimos si es posible, pero usualmente admin)
PrivilegesRequired=admin

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
spanish.UninstallShortcut=Desinstalar CipherPass
english.UninstallShortcut=Uninstall CipherPass

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Archivo ejecutable principal
Source: "dist\cipherpass.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Acceso directo en el menú de inicio
Name: "{group}\CipherPass"; Filename: "{app}\cipherpass.exe"; IconFilename: "{app}\cipherpass.exe"
; Acceso directo de desinstalación en el menú de inicio
Name: "{group}\{cm:UninstallShortcut}"; Filename: "{uninstallexe}"
; Acceso directo en el escritorio (opcional)
Name: "{autodesktop}\CipherPass"; Filename: "{app}\cipherpass.exe"; Tasks: desktopicon

[Run]
; Casilla para ejecutar al finalizar
Filename: "{app}\cipherpass.exe"; Description: "{cm:LaunchProgram,CipherPass}"; Flags: nowait postinstall skipifsilent
