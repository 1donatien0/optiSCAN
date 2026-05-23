; =============================================================================
; optiSCAN — Installateur Windows (Inno Setup)
; =============================================================================
; AppRelease = nom vM.m (v5.0) · AppVersion = semver / Directory.Build.props

#define AppName        "optiSCAN"
#define AppVersion     "5.0.0"
#define AppPublisher   "Dona By"
#define AppURL         "https://sourceforge.net/projects/optiscan/"
#define AppExeName     "optiSCAN.exe"
#define AppId          "{{F3A2C1D0-5B6E-4F7A-8C9D-0E1F2A3B4C5D}"
#define AppRelease     "v5.0"
#define AppIconFile    "..\optiSCAN\optiSCAN.ico"

; ── ISPP : emplacement de publish (VS / dotnet peuvent sortir dans publish\win-x64\ ou publish\)
; Préférer win-x64 en premier : c'est la sortie d'un « dotnet publish -r win-x64 » / profil dossier,
; et un vieux optiSCAN.exe à la racine de publish\ ne doit pas masquer une publication RID récente.
; Le .csproj supprime win-x64 / win-x86 / publish avant chaque publish (cible CleanStalePublishOutput).
#if FileExists(AddBackslash(SourcePath) + "..\optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\optiSCAN.exe")
  #define AppPublishSource "..\optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\*"
#elif FileExists(AddBackslash(SourcePath) + "..\optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\optiSCAN.exe")
  #define AppPublishSource "..\optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\*"
#else
  #expr Error("optiSCAN.exe introuvable. Ouvrez optiSCAN.csproj puis menu Build > Publish (Release), ou en ligne de commande : dotnet publish -c Release -r win-x64")
#endif

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppRelease} ({#AppVersion})
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
AppCopyright=Copyright 2026 Dona By
AppComments=optiSCAN {#AppRelease} ({#AppVersion}) — Antivirus (ClamAV + YARA) et optimisation système
SetupIconFile={#AppIconFile}
UninstallDisplayIcon={app}\{#AppExeName}
#if FileExists("..\LICENSE.txt")
LicenseFile=..\LICENSE.txt
#endif
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
OutputDir=.\output
OutputBaseFilename=optiSCAN_Setup_v{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
; no : évite un processus enfant LZMA parfois tué par l'antivirus (« Compile aborted » sans détail)
LZMAUseSeparateProcess=no
WizardStyle=modern
PrivilegesRequired=admin
MinVersion=10.0.17763
ArchitecturesAllowed=x86 x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
CloseApplicationsFilter=*.exe;*.dll
RestartApplications=no
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} — Installateur
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
VersionInfoCopyright=Copyright 2026 Dona By

[Languages]
Name: "french";  MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";   Description: "Créer une icône sur le Bureau";                              GroupDescription: "Icônes supplémentaires"
Name: "startupicon";   Description: "Lancer optiSCAN au démarrage de Windows";                   GroupDescription: "Options avancées"; Flags: unchecked
Name: "autoUpdateSig"; Description: "Activer les mises à jour auto des signatures (recommandé)"; GroupDescription: "Antivirus ClamAV"; Flags: checkedonce

[Files]
; ── Application principale ───────────────────────────────────────────────────
; Avant de compiler : Build > Publish (Release) ou : dotnet publish -c Release
; Le chemin exact est résolu par le préprocesseur (AppPublishSource).
; clamav\*, rules\* et yara\* sont exclus ici — gérés séparément ci-dessous.
Source: "{#AppPublishSource}"; DestDir: "{app}"; Excludes: "clamav\*,rules\*,yara\*"; Flags: ignoreversion recursesubdirs createallsubdirs
; ── ClamAV (architecture-specific) — ignoré si le dossier n'existe pas (clone partiel) ──
#if DirExists(AddBackslash(SourcePath) + "..\optiSCAN\clamav\x64")
Source: "..\optiSCAN\clamav\x64\*"; DestDir: "{app}\clamav\x64"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: IsWin64
#endif
#if DirExists(AddBackslash(SourcePath) + "..\optiSCAN\clamav\x86")
Source: "..\optiSCAN\clamav\x86\*"; DestDir: "{app}\clamav\x86"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: not IsWin64
#endif
; Certificat CVD (freshclam ≥ 1.5) — skip si absent (évite l'échec de compilation ISCC)
Source: "..\optiSCAN\clamav\certs\clamav.crt"; DestDir: "{app}\clamav\x64\certs"; Flags: ignoreversion skipifsourcedoesntexist; Check: IsWin64
Source: "..\optiSCAN\clamav\certs\clamav.crt"; DestDir: "{app}\clamav\x86\certs"; Flags: ignoreversion skipifsourcedoesntexist; Check: not IsWin64
Source: "..\optiSCAN\clamav\database\*"; DestDir: "{app}\clamav\database"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
; ── YARA ─────────────────────────────────────────────────────────────────────
Source: "..\optiSCAN\rules\*"; DestDir: "{app}\rules"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
Source: "..\optiSCAN\yara\*"; DestDir: "{app}\yara"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Désinstaller {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: startupicon

[Registry]
Root: HKCR; Subkey: "*\shell\Scanner avec optiSCAN"; ValueType: string; ValueData: ""; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\Scanner avec optiSCAN\command"; ValueType: string; ValueData: """{app}\{#AppExeName}"" --scan ""%1"""; Flags: uninsdeletekey
Root: HKCR; Subkey: "*\shell\Scanner avec optiSCAN"; ValueName: "Icon"; ValueType: string; ValueData: "{app}\{#AppExeName},0"
Root: HKCU; Subkey: "Software\optiSCAN"; ValueName: "AutoUpdateSignatures"; ValueType: dword; ValueData: "1"; Tasks: autoUpdateSig
Root: HKCU; Subkey: "Software\optiSCAN"; ValueName: "Version"; ValueType: string; ValueData: "{#AppVersion}"; Flags: uninsdeletekey

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Lancer {#AppName} maintenant"; Flags: nowait postinstall skipifsilent runascurrentuser

; =============================================================================
; CLEAN INSTALL — exécuté AVANT la copie des nouveaux fichiers
; =============================================================================
; Supprime les fichiers de configuration legacy susceptibles de contenir des
; chemins de la machine de dev ou la directive CVDCertsDirectory cassée
; (héritée des versions antérieures). Le code optiSCAN regénère un freshclam.conf
; propre dans %LocalAppData% au premier lancement de la mise à jour.
[InstallDelete]
; --- freshclam.conf legacy dans le dossier d'install ---
Type: files; Name: "{app}\clamav\x64\freshclam.conf"
Type: files; Name: "{app}\clamav\x86\freshclam.conf"
Type: files; Name: "{app}\clamav\freshclam.conf"
Type: files; Name: "{app}\clamav\x64\freshclam.conf.v1.bak"
Type: files; Name: "{app}\clamav\x86\freshclam.conf.v1.bak"
Type: files; Name: "{app}\clamav\x64\freshclam.conf.broken.bak"
Type: files; Name: "{app}\clamav\x86\freshclam.conf.broken.bak"

; --- clamd.conf legacy (peut avoir un BOM ou un path absolu de dev) ---
Type: files; Name: "{app}\clamav\x64\clamd.conf"
Type: files; Name: "{app}\clamav\x86\clamd.conf"

; --- freshclam.conf utilisateur potentiellement cassé (ancienne version) ---
; On ne touche PAS à la base de signatures (250 Mo) ni à la quarantaine.
Type: files; Name: "{localappdata}\optiSCAN\clamav\freshclam.conf"
Type: files; Name: "{localappdata}\optiSCAN\clamav\freshclam.conf.v1.bak"
Type: files; Name: "{localappdata}\optiSCAN\clamav\freshclam.conf.broken.bak"

; --- Verrous orphelins éventuels d'un freshclam précédent crashé ---
Type: files; Name: "{app}\clamav\database\freshclam.pid"
Type: files; Name: "{app}\clamav\database\mirrors.dat.lock"
Type: files; Name: "{app}\clamav\database\freshclam.dat.lock"

[UninstallDelete]
; Fichiers résiduels dans le dossier d'install
Type: filesandordirs; Name: "{app}\clamav\database"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\quarantine"
; Données utilisateur (préférences, historique, logs, quarantaine) — gérées
; en supplément par CurUninstallStepChanged ci-dessous, avec confirmation.

[Code]

function IsDotNet8Installed(): Boolean;
var
  Arch: string;
begin
  Result := False;

  if IsWin64 then
    Arch := 'x64'
  else
    Arch := 'x86';

  if RegKeyExists(HKLM, 'SOFTWARE\dotnet\Setup\InstalledVersions\' + Arch + '\sharedfx\Microsoft.WindowsDesktop.App') then
  begin
    Result := True;
    Exit;
  end;

  if RegKeyExists(HKLM, 'SOFTWARE\dotnet\Setup\InstalledVersions\' + Arch + '\sharedhost') then
  begin
    Result := True;
    Exit;
  end;

  if IsWin64 then
    Result := DirExists(ExpandConstant('{pf64}\dotnet\shared\Microsoft.WindowsDesktop.App'))
  else
    Result := DirExists(ExpandConstant('{pf}\dotnet\shared\Microsoft.WindowsDesktop.App'));
end;

function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;

  if not IsDotNet8Installed() then
  begin
    if MsgBox(
      '.NET 8 Desktop Runtime n''est pas installé sur cet ordinateur.' + #13#10 + #13#10 +
      'optiSCAN en a besoin pour fonctionner.' + #13#10 +
      'Voulez-vous être redirigé vers la page de téléchargement ?',
      mbConfirmation, MB_YESNO) = IDYES then
    begin
      ShellExec('open', 'https://dotnet.microsoft.com/en-us/download/dotnet/8.0', '', '', SW_SHOW, ewNoWait, ResultCode);
    end;
    Result := False;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  UserDataLocal: string;
  UserDataRoaming: string;
  Response: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    // 1. Toujours : suppression de la branche Registre HKCU\Software\optiSCAN
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\optiSCAN');

    // 2. Proposition : suppression des données utilisateur (quarantaine,
    //    historique, préférences, logs). On demande explicitement car
    //    l'utilisateur peut vouloir réinstaller plus tard et conserver son
    //    historique de scans.
    UserDataLocal := ExpandConstant('{localappdata}\optiSCAN');
    UserDataRoaming := ExpandConstant('{userappdata}\optiSCAN');

    if DirExists(UserDataLocal) or DirExists(UserDataRoaming) then
    begin
      Response := MsgBox(
        'Voulez-vous aussi supprimer toutes les données utilisateur d''optiSCAN ?' + #13#10 + #13#10 +
        '  • Historique des scans' + #13#10 +
        '  • Fichiers en quarantaine' + #13#10 +
        '  • Préférences et exclusions' + #13#10 +
        '  • Journaux et logs' + #13#10 + #13#10 +
        'Choisir « Non » conserve ces données pour une éventuelle réinstallation.',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2);

      if Response = IDYES then
      begin
        if DirExists(UserDataLocal) then
          DelTree(UserDataLocal, True, True, True);
        if DirExists(UserDataRoaming) then
          DelTree(UserDataRoaming, True, True, True);
      end;
    end;
  end;
end;

// =============================================================================
// CLEAN INSTALL — détecte une installation précédente et propose un reset
// =============================================================================
// Si l'utilisateur fait une mise à jour par-dessus une version antérieure buguée
// (avec un freshclam.conf cassé en LocalAppData), on propose de wiper le
// dossier de conf pour repartir sur des bases saines. La quarantaine et
// l'historique sont conservés.
procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfPath: string;
  Content: AnsiString;
  ShouldReset: Boolean;
begin
  if CurStep = ssInstall then
  begin
    ConfPath := ExpandConstant('{localappdata}\optiSCAN\clamav\freshclam.conf');
    if FileExists(ConfPath) then
    begin
      ShouldReset := False;

      // Détection automatique d'un conf cassé : contient CVDCertsDirectory
      // (directive qui faisait crasher freshclam dans les anciennes versions).
      if LoadStringFromFile(ConfPath, Content) then
      begin
        if Pos('CVDCertsDirectory', Content) > 0 then
          ShouldReset := True;
        // Détection BOM UTF-8 : si les 3 premiers octets sont EF BB BF,
        // c'est aussi un conf cassé qui fera échouer freshclam.
        if (Length(Content) >= 3) and (Ord(Content[1]) = $EF)
           and (Ord(Content[2]) = $BB) and (Ord(Content[3]) = $BF) then
          ShouldReset := True;
      end;

      if ShouldReset then
      begin
        DeleteFile(ConfPath);
        // Best effort : pas de message à l'utilisateur, c'est silencieux.
        // Le code optiSCAN regénérera un conf propre au premier clic
        // "Mettre à jour".
      end;
    end;
  end;
end;
