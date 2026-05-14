; =============================================================================
; optiSCAN v1.0 — Setup unique x86/x64
; Copie automatiquement les binaires ClamAV correspondants à l'architecture.
; =============================================================================

#define AppName      "optiSCAN"
#define AppVersion   "1.0.0"
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
SetupIconFile=..\optiSCAN\ico.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x86 x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
CloseApplicationsFilter=*.exe;*.dll
RestartApplications=no

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Créer une icône sur le Bureau"; GroupDescription: "Icônes supplémentaires"
Name: "startupicon"; Description: "Lancer optiSCAN au démarrage de Windows"; GroupDescription: "Options avancées"; Flags: unchecked
Name: "autoUpdateSignatures"; Description: "Activer les mises à jour auto des signatures (recommandé)"; GroupDescription: "Antivirus ClamAV"; Flags: checkedonce

[Files]
; Application publiée (AnyCPU/.NET) 
Source: "..\optiSCAN\bin\Release\net8.0-windows\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; ClamAV x64 pour OS 64-bit
Source: "..\optiSCAN\clamav\x64\*"; DestDir: "{app}\clamav\x64"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: IsWin64
; ClamAV x86 pour OS 32-bit
Source: "..\optiSCAN\clamav\x86\*"; DestDir: "{app}\clamav\x86"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: not IsWin64

; Base de signatures partagée (optionnelle)
Source: "..\optiSCAN\clamav\database\*"; DestDir: "{app}\clamav\database"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

[Icons]
Name: "{group}\optiSCAN"; Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\ico.ico"
Name: "{group}\Désinstaller optiSCAN"; Filename: "{uninstallexe}"
Name: "{autodesktop}\optiSCAN"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon; IconFilename: "{app}\ico.ico"
Name: "{userstartup}\optiSCAN"; Filename: "{app}\{#AppExeName}"; Tasks: startupicon

[Registry]
Root: HKCR; Subkey: "*\shell\Scanner avec optiSCAN"; ValueType: string; ValueData: ""; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\Scanner avec optiSCAN\command"; ValueType: string; ValueData: """{app}\{#AppExeName}"" --scan ""%1"""; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\Scanner avec optiSCAN"; ValueName: "Icon"; ValueType: string; ValueData: "{app}\ico.ico"
Root: HKCU; Subkey: "Software\optiSCAN"; ValueName: "AutoUpdateSignatures"; ValueType: dword; ValueData: "1"; Tasks: autoUpdateSignatures

[Run]
; Lancer optiSCAN après installation
Filename: "{app}\{#AppExeName}"; Description: "Lancer optiSCAN maintenant"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\clamav\database"

[Code]
function IsDotNet8Installed(): Boolean;
begin
  Result := False;
  if RegKeyExists(HKLM, 'SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedhost') then
    Result := True
  else if RegKeyExists(HKLM, 'SOFTWARE\dotnet\Setup\InstalledVersions\x86\sharedhost') then
    Result := True;
end;

function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
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
