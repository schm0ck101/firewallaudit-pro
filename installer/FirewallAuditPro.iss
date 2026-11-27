; Installateur Windows de FirewallAudit Pro (Inno Setup 6)
; Compilation : build.ps1 (ou ISCC.exe installer\FirewallAuditPro.iss)

#define AppName "FirewallAudit Pro"
#define AppVersion "1.0.15"
#define AppExe "FirewallAuditPro.exe"

[Setup]
AppId={{CDB0C3F8-A298-4F63-BCBC-3992826A6DAB}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=SCHMOCK
AppPublisherURL=https://schmock.fr
AppSupportURL=https://schmock.fr
AppCopyright=© 2026 SCHMOCK
DefaultDirName={autopf}\FirewallAudit Pro
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; Installation pour l'utilisateur courant par défaut (pas de droits admin requis)
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist
OutputBaseFilename=FirewallAuditPro-Setup-{#AppVersion}
SetupIconFile=..\assets\FirewallAuditPro.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Créer une icône sur le Bureau"; GroupDescription: "Raccourcis :"

[Files]
Source: "..\build\app\FirewallAuditPro\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Documentation"; Filename: "{app}\README.md"
Name: "{group}\Désinstaller {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon


[Run]
Filename: "{app}\{#AppExe}"; Description: "Lancer {#AppName}"; Flags: nowait postinstall skipifsilent
; mise à jour automatique (installateur lancé en mode silencieux par l'application) : relance une fois terminé
Filename: "{app}\{#AppExe}"; Flags: nowait postinstall skipifnotsilent runasoriginaluser

