; =============================================================================
; optiSCAN — Installateur Windows (Inno Setup)
; =============================================================================
; AppRelease = nom vM.m (v9.0) · AppVersion = semver / Directory.Build.props

#define AppName        "optiSCAN"
#ifndef AppVersion
#define AppVersion     "3.0.0"
#endif
#ifndef AppRelease
#define AppRelease     "v3.0"
#endif
#define AppPublisher   "Dona By"
#define AppURL         "https://sourceforge.net/projects/optiscan/"
#define AppExeName     "optiSCAN.exe"
#define AppId          "{{F3A2C1D0-5B6E-4F7A-8C9D-0E1F2A3B4C5D}"
#define AppIconFile    "..\optiSCAN\optiSCAN.ico"

; ── ISPP : emplacement de publish (VS / dotnet peuvent sortir dans publish\win-x64\ ou publish\)
; Préférer win-x64 en premier : c'est la sortie d'un « dotnet publish -r win-x64 » / profil dossier,
; et un vieux optiSCAN.exe à la racine de publish\ ne doit pas masquer une publication RID récente.
; Le .csproj supprime win-x64 / win-x86 / publish avant chaque publish (cible CleanStalePublishOutput).
; CI : /DAppPublishSource=..\publish\win-x64\*
#ifndef AppPublishSource
#if FileExists(AddBackslash(SourcePath) + "..\optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\optiSCAN.exe")
  #define AppPublishSource "..\optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\*"
#elif FileExists(AddBackslash(SourcePath) + "..\optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\optiSCAN.exe")
  #define AppPublishSource "..\optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\*"
#else
  #expr Error("optiSCAN.exe introuvable. Ouvrez optiSCAN.csproj puis menu Build > Publish (Release), ou en ligne de commande : dotnet publish -c Release -r win-x64")
#endif
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
; Même nom de fichier avec ou sans bases ClamAV embarquées.
OutputBaseFilename=optiSCAN_Setup_v{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
; no : évite un processus enfant LZMA parfois tué par l'antivirus (« Compile aborted » sans détail)
LZMAUseSeparateProcess=no
WizardStyle=modern
PrivilegesRequired=admin
MinVersion=10.0.17763
; x86 retiré : l'application est publiée en win-x64 uniquement (les binaires
; .NET copiés seraient inexécutables sur un Windows 32 bits).
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Même AppId : une 9.0.x déjà installée est mise à jour sur place (pas de désinstallation).
UsePreviousAppDir=yes
AppMutex=Global\optiSCAN_UniqueInstance
CloseApplications=force
CloseApplicationsFilter=optiSCAN.exe,optiSCAN.Service.exe
RestartApplications=no
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} — Installateur
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
VersionInfoCopyright=Copyright 2026 Dona By

; ── SIGNATURE DE CODE (Authenticode / EV) ───────────────────────────────────
; Sans signature : SmartScreen affiche « éditeur inconnu » et de nombreux
; antivirus bloquent l'installeur. Pour signer l'installeur (et le désinstalleur) :
;   1. Tools > Configure Sign Tools… dans l'IDE Inno, créer un outil nommé "signtool" :
;      signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a $f
;   2. Décommenter les deux lignes ci-dessous.
; (Laisser commenté tant qu'aucun certificat n'est configuré, sinon ISCC échoue.)
;SignTool=signtool $f
;SignedUninstaller=yes

; Langue de l'installateur = langue de l'application (UiCulture en Registre).
ShowLanguageDialog=auto

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
; Profil d'install allégé façon v8 : défaut = UI + ClamAV + YARA (+ MAJ signatures).
; Service plateforme / RTP avancé = opt-in explicite (Flags: unchecked).
Name: "desktopicon";   Description: "Créer une icône sur le Bureau";                              GroupDescription: "Icônes supplémentaires"
Name: "startupicon";   Description: "Lancer optiSCAN au démarrage de Windows";                   GroupDescription: "Options avancées"; Flags: unchecked
Name: "autoUpdateSig"; Description: "Activer les mises à jour auto des signatures (recommandé)"; GroupDescription: "Moteurs ClamAV + YARA"; Flags: checkedonce
Name: "platformservice"; Description: "Installer le service Windows de protection système v9 (RTP/AMSI/IPC — avancé)"; GroupDescription: "Protection avancée (optionnel)"; Flags: unchecked

[Files]
; ── Application principale ───────────────────────────────────────────────────
; Avant de compiler : Build > Publish (Release) ou : dotnet publish -c Release
; Le chemin exact est résolu par le préprocesseur (AppPublishSource).
; clamav\*, rules\* et yara\* sont exclus ici — gérés séparément ci-dessous.
Source: "{#AppPublishSource}"; DestDir: "{app}"; Excludes: "clamav\*,rules\*,yara\*"; Flags: ignoreversion recursesubdirs createallsubdirs
; ── ClamAV x64 — outils développeur exclus (sigtool/clambc & co : ~47 Mo
; inutiles au scan et à la mise à jour ; le code n'y fait jamais appel) ──────
#if DirExists(AddBackslash(SourcePath) + "..\optiSCAN\clamav\x64")
Source: "..\optiSCAN\clamav\x64\*"; DestDir: "{app}\clamav\x64"; Excludes: "sigtool.exe,clambc.exe,clamdtop.exe,clamsubmit.exe,clamconf.exe"; Flags: ignoreversion recursesubdirs createallsubdirs
#endif
; Certificat CVD (freshclam ≥ 1.5) — skip si absent (évite l'échec de compilation ISCC)
Source: "..\optiSCAN\clamav\certs\clamav.crt"; DestDir: "{app}\clamav\x64\certs"; Flags: ignoreversion skipifsourcedoesntexist
; Offline complet (DB ClamAV + règles YARA) : iscc /DEmbedOfflineSignatures
#ifdef EmbedOfflineSignatures
  #define EmbedClamAvDatabase
  #define EmbedYaraRules
#endif
; ── Base de signatures ClamAV (~105 Mo incompressibles) ─────────────────────
; Par défaut : NON embarquée — freshclam / bouton MAJ signatures les télécharge
; après installation (réseau requis au 1er lancement). Aligné setup v8 léger.
; Offline : /DEmbedClamAvDatabase ou /DEmbedOfflineSignatures
#ifdef EmbedClamAvDatabase
Source: "..\optiSCAN\clamav\database\*"; DestDir: "{app}\clamav\database"; Excludes: "*.log"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
#endif
; ── YARA : binaire toujours embarqué ; règles .yar optionnelles ───────────────
; Par défaut : règles NON embarquées — YARA-Forge / MAJ signatures au 1er lancement.
; Offline : /DEmbedYaraRules ou /DEmbedOfflineSignatures
#ifdef EmbedYaraRules
Source: "..\optiSCAN\rules\*"; DestDir: "{app}\rules"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
#endif
Source: "..\optiSCAN\yara\*"; DestDir: "{app}\yara"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
; ── Service Windows (pour tâche platformservice opt-in) ───────────────────────
; Chemin dédié : AppPublishSource finit par \* et ne peut pas servir de préfixe fichier.
Source: "..\optiSCAN\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\optiSCAN.Service.exe"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\optiSCAN.Service\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\optiSCAN.Service.exe"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
; Script exclusions Defender : copié pour usage manuel / depuis l'app — PAS exécuté
; automatiquement à l'install (évite le marqueur heuristique « tamper » post-v8).
Source: "..\scripts\add-defender-exclusions.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
; AMSI / minifiltre — comme v8 : livrés s'ils existent sur la machine de build
; (skipifsourcedoesntexist). Sans signature Authenticode/EV ils restent inopérants
; sous Windows x64, mais disponibles pour tests / builds signés ultérieurs.
Source: "..\native\optiSCAN.AmsiProvider\x64\Release\optiSCAN.AmsiProvider.dll"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\native\optiSCAN.Minifilter\x64\optiSCAN.Minifilter.sys"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
; ── Runtime .NET 8 Desktop embarqué (OPTIONNEL, ~56 Mo) ──────────────────────
; Placer windowsdesktop-runtime-8.0.x-win-x64.exe renommé en
; installer\redist\windowsdesktop-runtime-win-x64.exe pour un installeur
; autonome (hors-ligne). Absent → l'installeur télécharge le runtime si besoin.
#define DotNetRedist "redist\windowsdesktop-runtime-win-x64.exe"
#if FileExists(AddBackslash(SourcePath) + DotNetRedist)
  #define HasDotNetRedist
Source: "{#DotNetRedist}"; DestDir: "{tmp}"; DestName: "windowsdesktop-runtime-8.0.exe"; Flags: dontcopy
#endif

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Désinstaller {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: startupicon

[Registry]
; Menu contextuel Explorateur : enregistré en [Code] selon la langue de l'installateur (HKCU\Software\Classes).
Root: HKCU; Subkey: "Software\optiSCAN"; ValueName: "AutoUpdateSignatures"; ValueType: dword; ValueData: "1"; Tasks: autoUpdateSig
Root: HKCU; Subkey: "Software\optiSCAN"; ValueName: "Version"; ValueType: string; ValueData: "{#AppVersion}"; Flags: uninsdeletekey
; UiCulture est réécrit à chaque install / mise à jour (fr-FR ou en-US selon la langue Inno).

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

// ── .NET 8 Desktop Runtime : auto-installation (plus de blocage) ─────────────
// Si le runtime manque, il est téléchargé (lien « latest » officiel Microsoft)
// puis installé silencieusement avant la copie des fichiers. L'ancien
// comportement (blocage + redirection navigateur) ne reste qu'en secours
// si le téléchargement échoue (machine hors-ligne).
var
  DotNetDownloadPage: TDownloadWizardPage;

function DotNetRuntimeUrl(): string;
begin
  if IsWin64 then
    Result := 'https://aka.ms/dotnet/8.0/windowsdesktop-runtime-win-x64.exe'
  else
    Result := 'https://aka.ms/dotnet/8.0/windowsdesktop-runtime-win-x86.exe';
end;

function OnDotNetDownloadProgress(const Url, FileName: string; const Progress, ProgressMax: Int64): Boolean;
begin
  Result := True; // ne pas annuler
end;

procedure InitializeWizard();
begin
  if ActiveLanguage = 'english' then
    DotNetDownloadPage := CreateDownloadPage(
      'Installing .NET 8 Desktop Runtime',
      'optiSCAN requires the .NET 8 Desktop Runtime. It is being downloaded and installed automatically — no action needed.',
      @OnDotNetDownloadProgress)
  else
    DotNetDownloadPage := CreateDownloadPage(
      'Installation de .NET 8 Desktop Runtime',
      'optiSCAN nécessite .NET 8 Desktop Runtime. Téléchargement et installation automatiques en cours — aucune action requise.',
      @OnDotNetDownloadProgress);
end;

function RunDotNetRuntimeInstaller(): Boolean;
var
  ResultCode: Integer;
begin
  Result := False;
  if not Exec(ExpandConstant('{tmp}\windowsdesktop-runtime-8.0.exe'),
              '/install /quiet /norestart', '', SW_SHOW,
              ewWaitUntilTerminated, ResultCode) then
    Exit;
  // 0 = OK · 3010 = OK, redémarrage requis · 1638 = version déjà présente
  Result := (ResultCode = 0) or (ResultCode = 3010) or (ResultCode = 1638);
end;

procedure OfferDotNetDownloadPage();
var
  ResultCode: Integer;
begin
  if ActiveLanguage = 'english' then
  begin
    if MsgBox(
      'The .NET 8 Desktop Runtime could not be installed automatically' + #13#10 +
      '(no Internet connection or download error).' + #13#10 + #13#10 +
      'Would you like to open the download page to install it manually?',
      mbConfirmation, MB_YESNO) = IDYES then
      ShellExec('open', 'https://dotnet.microsoft.com/en-us/download/dotnet/8.0', '', '', SW_SHOW, ewNoWait, ResultCode);
  end
  else
  if MsgBox(
    'Le runtime .NET 8 Desktop n''a pas pu être installé automatiquement' + #13#10 +
    '(pas de connexion Internet ou erreur de téléchargement).' + #13#10 + #13#10 +
    'Voulez-vous ouvrir la page de téléchargement pour l''installer manuellement ?',
    mbConfirmation, MB_YESNO) = IDYES then
    ShellExec('open', 'https://dotnet.microsoft.com/en-us/download/dotnet/8.0', '', '', SW_SHOW, ewNoWait, ResultCode);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = wpReady) and (not IsDotNet8Installed()) then
  begin
#ifdef HasDotNetRedist
    // Runtime embarqué dans l'installeur : extraction + installation locale,
    // aucun téléchargement (fonctionne hors-ligne).
    ExtractTemporaryFile('windowsdesktop-runtime-8.0.exe');
    if not RunDotNetRuntimeInstaller() then
    begin
      OfferDotNetDownloadPage();
      Result := False; // rester sur la page « Prêt à installer »
    end;
#else
    DotNetDownloadPage.Clear;
    DotNetDownloadPage.Add(DotNetRuntimeUrl(), 'windowsdesktop-runtime-8.0.exe', '');
    DotNetDownloadPage.Show;
    try
      try
        DotNetDownloadPage.Download;
        if not RunDotNetRuntimeInstaller() then
        begin
          OfferDotNetDownloadPage();
          Result := False; // rester sur la page « Prêt à installer »
        end;
      except
        OfferDotNetDownloadPage();
        Result := False;
      end;
    finally
      DotNetDownloadPage.Hide;
    end;
#endif
  end;
end;

procedure RemoveExplorerShellMenu(const Root: Integer; const ParentKey, MenuKey: string);
begin
  if RegKeyExists(Root, ParentKey + '\' + MenuKey) then
    RegDeleteKeyIncludingSubkeys(Root, ParentKey + '\' + MenuKey);
end;

procedure UnregisterExplorerContextMenus();
begin
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\*\shell', 'optiSCAN.Scan');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\*\shell', 'Scanner avec optiSCAN');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\*\shell', 'Scan with optiSCAN');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\*\shell', 'Scanner avec optiCombat');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\*\shell', 'Scan with optiCombat');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\*\shell', 'ScanWithOptiSCAN');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\*\shell', 'ScanWithOptiCombat');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\*\shell', 'Shell_ScanWith');

  RemoveExplorerShellMenu(HKCU, 'Software\Classes\Directory\shell', 'optiSCAN.Scan');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\Directory\shell', 'Scanner avec optiSCAN');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\Directory\shell', 'Scan with optiSCAN');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\Directory\shell', 'Scanner avec optiCombat');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\Directory\shell', 'Scan with optiCombat');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\Directory\shell', 'ScanWithOptiSCAN');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\Directory\shell', 'ScanWithOptiCombat');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\Directory\shell', 'Shell_ScanWith');

  RemoveExplorerShellMenu(HKCR, '*\shell', 'optiSCAN.Scan');
  RemoveExplorerShellMenu(HKCR, '*\shell', 'Scanner avec optiSCAN');
  RemoveExplorerShellMenu(HKCR, '*\shell', 'Scan with optiSCAN');
  RemoveExplorerShellMenu(HKCR, '*\shell', 'Scanner avec optiCombat');
  RemoveExplorerShellMenu(HKCR, '*\shell', 'Scan with optiCombat');
  RemoveExplorerShellMenu(HKCR, '*\shell', 'ScanWithOptiSCAN');
  RemoveExplorerShellMenu(HKCR, '*\shell', 'ScanWithOptiCombat');
  RemoveExplorerShellMenu(HKCR, '*\shell', 'Shell_ScanWith');

  RemoveExplorerShellMenu(HKCR, 'Directory\shell', 'optiSCAN.Scan');
  RemoveExplorerShellMenu(HKCR, 'Directory\shell', 'Scanner avec optiSCAN');
  RemoveExplorerShellMenu(HKCR, 'Directory\shell', 'Scan with optiSCAN');
  RemoveExplorerShellMenu(HKCR, 'Directory\shell', 'Scanner avec optiCombat');
  RemoveExplorerShellMenu(HKCR, 'Directory\shell', 'Scan with optiCombat');
  RemoveExplorerShellMenu(HKCR, 'Directory\shell', 'ScanWithOptiSCAN');
  RemoveExplorerShellMenu(HKCR, 'Directory\shell', 'ScanWithOptiCombat');
  RemoveExplorerShellMenu(HKCR, 'Directory\shell', 'Shell_ScanWith');
end;

procedure UnregisterOptiScanSystemArtifacts();
var
  ResultCode: Integer;
begin
  UnregisterExplorerContextMenus();
  RegDeleteKeyIncludingSubkeys(HKCU, 'Software\optiSCAN');

  Exec('schtasks.exe', '/Delete /TN "optiSCAN_DailyScan" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('schtasks.exe', '/Delete /TN "optiSCAN_Watchdog" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  Exec('fltmc.exe', 'unload optiSCANMinifilter', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('sc.exe', 'stop optiSCANProtectionV9', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('sc.exe', 'delete optiSCANProtectionV9', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('sc.exe', 'stop optiSCANProtectionV8', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('sc.exe', 'delete optiSCANProtectionV8', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  if RegKeyExists(HKLM, 'SOFTWARE\Microsoft\AMSI\Providers\{A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}') then
    RegDeleteKeyIncludingSubkeys(HKLM, 'SOFTWARE\Microsoft\AMSI\Providers\{A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}');

  if DirExists(ExpandConstant('{commonappdata}\optiSCAN')) then
    DelTree(ExpandConstant('{commonappdata}\optiSCAN'), True, True, True);
end;

function InitializeUninstall(): Boolean;
begin
  UnregisterOptiScanSystemArtifacts();
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  UserDataLocal: string;
  UserDataRoaming: string;
  Response: Integer;
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
    UnregisterOptiScanSystemArtifacts();

  if CurUninstallStep = usPostUninstall then
  begin
    UnregisterOptiScanSystemArtifacts();
    // Proposition : suppression des données utilisateur (quarantaine, historique, préférences, logs).
    UserDataLocal := ExpandConstant('{localappdata}\optiSCAN');
    UserDataRoaming := ExpandConstant('{userappdata}\optiSCAN');

    if DirExists(UserDataLocal) or DirExists(UserDataRoaming) then
    begin
      if ActiveLanguage = 'english' then
        Response := MsgBox(
          'Do you also want to remove all optiSCAN user data?' + #13#10 + #13#10 +
          '  • Scan history' + #13#10 +
          '  • Quarantined files' + #13#10 +
          '  • Preferences and exclusions' + #13#10 +
          '  • Logs' + #13#10 + #13#10 +
          'Choose No to keep this data for a future reinstall.',
          mbConfirmation, MB_YESNO or MB_DEFBUTTON2)
      else
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
procedure WriteInstallerUiCulture();
begin
  if ActiveLanguage = 'english' then
    RegWriteStringValue(HKCU, 'Software\optiSCAN', 'UiCulture', 'en-US')
  else
    RegWriteStringValue(HKCU, 'Software\optiSCAN', 'UiCulture', 'fr-FR');
end;

procedure RegisterExplorerContextMenu();
var
  MenuKey, MenuLabel, ExePath, Cmd: string;
begin
  if ActiveLanguage = 'english' then
    MenuLabel := 'Scan with optiSCAN'
  else
    MenuLabel := 'Scanner avec optiSCAN';

  MenuKey := 'optiSCAN.Scan';
  ExePath := ExpandConstant('{app}\{#AppExeName}');
  Cmd := '"' + ExePath + '" --scan "%1"';

  UnregisterExplorerContextMenus();

  RegWriteStringValue(HKCU, 'Software\Classes\*\shell\' + MenuKey, '', MenuLabel);
  RegWriteStringValue(HKCU, 'Software\Classes\*\shell\' + MenuKey, 'Icon', ExePath + ',0');
  RegWriteStringValue(HKCU, 'Software\Classes\*\shell\' + MenuKey + '\command', '', Cmd);

  RegWriteStringValue(HKCU, 'Software\Classes\Directory\shell\' + MenuKey, '', MenuLabel);
  RegWriteStringValue(HKCU, 'Software\Classes\Directory\shell\' + MenuKey, 'Icon', ExePath + ',0');
  RegWriteStringValue(HKCU, 'Software\Classes\Directory\shell\' + MenuKey + '\command', '', Cmd);
end;

// Exclusions Defender : volontairement NON appelées ici (profil allégé v8).
// Le script reste dans {app}\scripts pour un opt-in depuis l'application.

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfPath: string;
  Content: AnsiString;
  ShouldReset: Boolean;
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    WriteInstallerUiCulture();
    RegisterExplorerContextMenu();
    if IsTaskSelected('platformservice') then
    begin
      if FileExists(ExpandConstant('{app}\optiSCAN.Service.exe')) then
      begin
        Exec('sc.exe', 'create optiSCANProtectionV9 binPath= "\"' + ExpandConstant('{app}\optiSCAN.Service.exe') + '\"" start= auto DisplayName= "optiSCAN Protection v9"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        Exec('sc.exe', 'description optiSCANProtectionV9 "Moteur de protection optiSCAN v9 (RTP, AMSI, IPC)"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        Exec('sc.exe', 'start optiSCANProtectionV9', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      end
      else
      begin
        if ActiveLanguage = 'english' then
          MsgBox('The system protection service (optiSCAN.Service.exe) was not included in this build. Real-time protection (RTP/AMSI/IPC) will be unavailable.', mbInformation, MB_OK)
        else
          MsgBox('Le service de protection système (optiSCAN.Service.exe) n''est pas inclus dans cette version. La protection temps réel (RTP/AMSI/IPC) sera indisponible.', mbInformation, MB_OK);
      end;
    end;
  end;

  if CurStep = ssInstall then
  begin
    // Le service et l'exe verrouillent {app}. Sans cet arrêt, Windows refuse
    // le remplacement et l'utilisateur doit désinstaller à la main.
    Exec('taskkill.exe', '/F /IM optiSCAN.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('taskkill.exe', '/F /IM optiSCAN.Service.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('sc.exe', 'stop optiSCANProtectionV9', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('sc.exe', 'stop optiSCANProtectionV8', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

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
