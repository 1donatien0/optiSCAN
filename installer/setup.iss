; =============================================================================
; optiSCAN v2.0 — Script d'installation Inno Setup
; Inclut : application WPF + ClamAV binaires + base de signatures initiale
; =============================================================================
; Prérequis : Inno Setup 6.x  https://jrsoftware.org/isinfo.php
;             .NET 8 Runtime (téléchargé automatiquement si absent)
; =============================================================================

#define AppName      "optiSCAN"
#define AppVersion   "2.0.0"
#define AppPublisher "optiSCAN"
#define AppURL       "http://anthony-cardinale.fr/pc-cleaner"
#define AppExeName   "optiSCAN.exe"
#define AppId        "{{F3A2C1D0-5B6E-4F7A-8C9D-0E1F2A3B4C5D}"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\optiSCAN
DefaultGroupName=optiSCAN
AllowNoIcons=yes
LicenseFile=..\LICENSE.txt
OutputDir=.\output
OutputBaseFilename=optiSCAN_Setup_v{#AppVersion}
SetupIconFile=..\LogicielNettoyagePC\ico.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardImageFile=wizard_banner.bmp
WizardSmallImageFile=wizard_small.bmp

; Droits administrateur requis (ClamAV nécessite les droits pour scanner le système)
PrivilegesRequired=admin

; .NET 8 Desktop Runtime (vérifié avant installation)
CloseApplications=yes
CloseApplicationsFilter=*.exe;*.dll
RestartApplications=no

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";       Description: "Créer une icône sur le Bureau";     GroupDescription: "Icônes supplémentaires"
Name: "startupicon";       Description: "Lancer optiSCAN au démarrage de Windows"; GroupDescription: "Options avancées"; Flags: unchecked
Name: "autoUpdateSignatures"; Description: "Activer les mises à jour auto des signatures (recommandé)"; GroupDescription: "Antivirus ClamAV"; Flags: checkedonce

[Files]
; ── Application principale ──────────────────────────────────────────────────
Source: "..\LogicielNettoyagePC\bin\Release\net8.0-windows\publish\*";
  DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; ── Binaires ClamAV (à placer dans build\clamav\ avant de compiler le setup) ──
; Télécharger depuis : https://www.clamav.net/downloads#otherversions  (Windows 64-bit)
Source: "..\build\clamav\clamscan.exe";   DestDir: "{app}\clamav"; Flags: ignoreversion
Source: "..\build\clamav\freshclam.exe";  DestDir: "{app}\clamav"; Flags: ignoreversion
Source: "..\build\clamav\clamd.exe";      DestDir: "{app}\clamav"; Flags: ignoreversion
Source: "..\build\clamav\libclamav.dll";  DestDir: "{app}\clamav"; Flags: ignoreversion
Source: "..\build\clamav\libssl-*.dll";   DestDir: "{app}\clamav"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\build\clamav\libcrypto-*.dll"; DestDir: "{app}\clamav"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\build\clamav\*.dll";          DestDir: "{app}\clamav"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\build\clamav\conf_examples\*"; DestDir: "{app}\clamav"; Flags: ignoreversion skipifsourcedoesntexist

; ── Base de signatures initiale (optionnelle — évite le téléchargement au premier lancement) ──
; Générer avec : freshclam --datadir=.\database
Source: "..\build\clamav\database\main.cvd";  DestDir: "{app}\clamav\database"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\build\clamav\database\daily.cvd"; DestDir: "{app}\clamav\database"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\build\clamav\database\bytecode.cvd"; DestDir: "{app}\clamav\database"; Flags: ignoreversion skipifsourcedoesntexist

; ── Configuration freshclam ──────────────────────────────────────────────────
Source: "..\build\clamav\freshclam.conf"; DestDir: "{app}\clamav"; Flags: ignoreversion onlyifdoesntexist skipifsourcedoesntexist

[Icons]
Name: "{group}\optiSCAN";          Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\ico.ico"
Name: "{group}\Désinstaller optiSCAN"; Filename: "{uninstallexe}"
Name: "{autodesktop}\optiSCAN";    Filename: "{app}\{#AppExeName}"; Tasks: desktopicon; IconFilename: "{app}\ico.ico"
Name: "{userstartup}\optiSCAN";    Filename: "{app}\{#AppExeName}"; Tasks: startupicon

[Registry]
; Association de fichier optionnelle (scan de fichier via clic-droit Windows Explorer)
Root: HKCR; Subkey: "*\shell\Scanner avec optiSCAN";                    ValueType: string; ValueData: ""; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\Scanner avec optiSCAN\command";             ValueType: string; ValueData: """{app}\{#AppExeName}"" --scan ""%1"""; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\Scanner avec optiSCAN";                    ValueName: "Icon"; ValueType: string; ValueData: "{app}\ico.ico"

; Clé pour les mises à jour auto (tâche planifiée freshclam)
Root: HKCU; Subkey: "Software\optiSCAN";  ValueName: "AutoUpdateSignatures"; ValueType: dword;
  ValueData: "1"; Tasks: autoUpdateSignatures

[Run]
; Lancement de freshclam après installation (première mise à jour des signatures)
Filename: "{app}\clamav\freshclam.exe";
  Parameters: "--config-file=""{app}\clamav\freshclam.conf"" --datadir=""{app}\clamav\database""";
  Description: "Télécharger les signatures antivirus (recommandé)";
  Flags: postinstall shellexec skipifsilent; Tasks: autoUpdateSignatures

; Lancer optiSCAN après installation
Filename: "{app}\{#AppExeName}";
  Description: "Lancer optiSCAN maintenant";
  Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\clamav\database"
Type: filesandordirs; Name: "{app}\clamav\freshclam.log"

[Code]
// ── Vérification .NET 8 avant installation ──────────────────────────────────
function IsDotNet8Installed(): Boolean;
var
  ResultCode: Integer;
begin
  Result := False;
  // Vérifie la présence de .NET 8 via la clé de registre
  if RegKeyExists(HKLM, 'SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedhost') then
    Result := True;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsDotNet8Installed() then
  begin
    if MsgBox(
      '.NET 8 Desktop Runtime n''est pas installé.' + #13#10 +
      'Voulez-vous être redirigé vers la page de téléchargement ?',
      mbConfirmation, MB_YESNO) = IDYES then
    begin
      ShellExec('open',
        'https://dotnet.microsoft.com/en-us/download/dotnet/8.0',
        '', '', SW_SHOW, ewNoWait, ResultCode);
    end;
    Result := False;
  end;
end;
