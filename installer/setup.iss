; =============================================================================
; optiSCAN — Installateur Windows (Inno Setup)
; =============================================================================
; AppRelease = nom vM.m (v1.0) · AppVersion = semver / Directory.Build.props

#define AppName        "optiSCAN"
#define AppDirName     "optiSCAN WinUI"
#ifndef AppVersion
#define AppVersion     "1.0.0"
#endif
#ifndef AppRelease
#define AppRelease     "v1.0"
#endif
#define AppPublisher   "Dona By"
#define AppURL         "https://sourceforge.net/projects/optiscan/"
#define AppExeName     "optiSCAN.exe"
#define AppId          "{{8680BFF9-04E1-4E70-BC9C-390B312CB7CE}"
#define AppIconFile    "..\optiSCAN\optiSCAN.ico"

; ── ISPP : emplacement de publish (VS / dotnet peuvent sortir dans publish\win-x64\ ou publish\)
; Préférer win-x64 en premier : c'est la sortie d'un « dotnet publish -r win-x64 » / profil dossier,
; et un vieux optiSCAN.exe à la racine de publish\ ne doit pas masquer une publication RID récente.
; Le .csproj supprime win-x64 / win-x86 / publish avant chaque publish (cible CleanStalePublishOutput).
; CI : /DAppPublishSource=..\publish\win-x64\*
#ifndef AppPublishSource
#if FileExists(AddBackslash(SourcePath) + "..\optiSCAN.WinUI\bin\Release\net10.0-windows10.0.19041.0\publish\win-x64\optiSCAN.exe")
  #define AppPublishSource "..\optiSCAN.WinUI\bin\Release\net10.0-windows10.0.19041.0\publish\win-x64\*"
#elif FileExists(AddBackslash(SourcePath) + "..\publish\win-x64\optiSCAN.exe")
  #define AppPublishSource "..\publish\win-x64\*"
#else
  #expr Error("optiSCAN.exe introuvable. Publiez d'abord vers optiSCAN.WinUI\bin\Release\net10.0-windows10.0.19041.0\publish\win-x64\ (VS : FolderProfile), ou : dotnet publish optiSCAN.WinUI\optiSCAN.WinUI.csproj -c Release -p:PublishProfile=FolderProfile")
#endif
#endif

; Version du Windows App Runtime requise (doit suivre Microsoft.WindowsAppSDK 1.8.x du .csproj).
#ifndef WinAppRuntimeVersion
#define WinAppRuntimeVersion "1.8"
#endif

; Détection du mode de publication (build-release-setup.ps1 passe ces /D explicitement ;
; repli ici pour un ISCC lancé à la main sur le dossier publish par défaut).
; SelfContainedPublish          : runtime .NET embarqué (System.Private.CoreLib.dll présent).
; WinAppSdkSelfContainedPublish : Windows App SDK embarqué (Microsoft.WindowsAppRuntime.dll présent).
#define PublishProbeDir StringChange(AppPublishSource, "\*", "")
#ifndef SelfContainedPublish
#if FileExists(AddBackslash(SourcePath) + PublishProbeDir + "\System.Private.CoreLib.dll")
  #define SelfContainedPublish
#endif
#endif
#ifndef WinAppSdkSelfContainedPublish
#if FileExists(AddBackslash(SourcePath) + PublishProbeDir + "\Microsoft.WindowsAppRuntime.dll")
  #define WinAppSdkSelfContainedPublish
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
DefaultDirName={autopf}\{#AppDirName}
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

[CustomMessages]
french.PlatformGroup=Protection système (à venir)
english.PlatformGroup=System protection (planned)
french.PlatformTask=Service Windows de protection système — prévu dans 3 à 5 ans (pilote noyau signé requis, indisponible dans cette version)
english.PlatformTask=Windows system protection service — planned in 3 to 5 years (signed kernel driver required, unavailable in this version)

[Tasks]
Name: "desktopicon";   Description: "Créer une icône sur le Bureau";                              GroupDescription: "Icônes supplémentaires"
Name: "startupicon";   Description: "Lancer optiSCAN au démarrage de Windows";                   GroupDescription: "Options avancées"; Flags: unchecked
Name: "autoUpdateSig"; Description: "Activer les mises à jour auto des signatures (recommandé)"; GroupDescription: "Antivirus ClamAV"; Flags: checkedonce
; Service + minifiltre : prévus dans 3 à 5 ans (pilote signé). Case visible mais grisée.
; La protection temps réel de l'application fonctionne sans ce service.
Name: "platformservice"; Description: "{cm:PlatformTask}"; GroupDescription: "{cm:PlatformGroup}"; Flags: unchecked

[Files]
; ── Application principale ───────────────────────────────────────────────────
; Avant de compiler : Build > Publish (Release) ou : dotnet publish -c Release
; Le chemin exact est résolu par le préprocesseur (AppPublishSource).
; clamav\*, rules\* et yara\* sont exclus ici — gérés séparément ci-dessous.
Source: "{#AppPublishSource}"; DestDir: "{app}"; Excludes: "clamav\*,rules\*,yara\*"; Flags: ignoreversion recursesubdirs createallsubdirs
; ── ClamAV (outils dev sigtool/clambc & co exclus, comme optiCombat) — ignoré si le dossier n'existe pas (clone partiel) ──
#if DirExists(AddBackslash(SourcePath) + "..\optiSCAN\clamav\x64")
Source: "..\optiSCAN\clamav\x64\*"; DestDir: "{app}\clamav\x64"; Excludes: "sigtool.exe,clambc.exe,clamdtop.exe,clamsubmit.exe,clamconf.exe"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: IsWin64
#endif
#if DirExists(AddBackslash(SourcePath) + "..\optiSCAN\clamav\x86")
Source: "..\optiSCAN\clamav\x86\*"; DestDir: "{app}\clamav\x86"; Excludes: "sigtool.exe,clambc.exe,clamdtop.exe,clamsubmit.exe,clamconf.exe"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: not IsWin64
#endif
; Certificat CVD (freshclam ≥ 1.5) — skip si absent (évite l'échec de compilation ISCC)
Source: "..\optiSCAN\clamav\certs\clamav.crt"; DestDir: "{app}\clamav\x64\certs"; Flags: ignoreversion skipifsourcedoesntexist; Check: IsWin64
Source: "..\optiSCAN\clamav\certs\clamav.crt"; DestDir: "{app}\clamav\x86\certs"; Flags: ignoreversion skipifsourcedoesntexist; Check: not IsWin64
; Bases .cvd / .cld volontairement absentes : freshclam les télécharge au premier lancement
; (SignatureUpdatePolicy). Les embarquer ajoute ~100 Mo à l'installeur.
; ── YARA ─────────────────────────────────────────────────────────────────────
Source: "..\optiSCAN\rules\*"; DestDir: "{app}\rules"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
Source: "..\optiSCAN\yara\*"; DestDir: "{app}\yara"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
; ── Service Windows + composants natifs (optionnels si non compilés) ───────────
Source: "{#AppPublishSource}\optiSCAN.Service.exe"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\native\optiSCAN.AmsiProvider\x64\Release\optiSCAN.AmsiProvider.dll"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\native\optiSCAN.Minifilter\x64\optiSCAN.Minifilter.sys"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\scripts\add-defender-exclusions.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion

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

// ─────────────────────────────────────────────────────────────────────────────
// Prérequis (publication « framework-dependent », profil FolderProfile par défaut) :
//   • .NET 10 Desktop Runtime (Microsoft.WindowsDesktop.App 10.x)
//   • Windows App Runtime {#WinAppRuntimeVersion} (Windows App SDK non empaqueté)
// Absents → proposés en téléchargement (redistribuables officiels Microsoft)
// puis installés silencieusement avant la copie des fichiers.
// Publication self-contained (-SelfContained) : ISPP définit SelfContainedPublish /
// WinAppSdkSelfContainedPublish et les contrôles correspondants sont ignorés.
// ─────────────────────────────────────────────────────────────────────────────
var
  PrereqDownloadPage: TDownloadWizardPage;
  NeedDotNet: Boolean;
  NeedWinAppRuntime: Boolean;

function ArchSuffix(): string;
begin
  if IsWin64 then
    Result := 'x64'
  else
    Result := 'x86';
end;

function RegHasDotNet10Desktop(const RootKey: Integer): Boolean;
var
  Names: TArrayOfString;
  I: Integer;
begin
  Result := False;
  if RegGetValueNames(RootKey,
       'SOFTWARE\dotnet\Setup\InstalledVersions\' + ArchSuffix() + '\sharedfx\Microsoft.WindowsDesktop.App',
       Names) then
    for I := 0 to GetArrayLength(Names) - 1 do
      if Copy(Names[I], 1, 3) = '10.' then
      begin
        Result := True;
        Exit;
      end;
end;

// Exige une version 10.x du runtime Desktop (une autre version majeure ne suffit pas).
function IsDotNet10DesktopInstalled(): Boolean;
var
  FindRec: TFindRec;
  Root: string;
begin
  Result := RegHasDotNet10Desktop(HKLM32);
  if (not Result) and IsWin64 then
    Result := RegHasDotNet10Desktop(HKLM64);
  if Result then
    Exit;

  if IsWin64 then
    Root := ExpandConstant('{commonpf64}')
  else
    Root := ExpandConstant('{commonpf32}');
  if FindFirst(Root + '\dotnet\shared\Microsoft.WindowsDesktop.App\10.*', FindRec) then
  begin
    Result := True;
    FindClose(FindRec);
  end;
end;

// Framework + paquet Main du Windows App Runtime (requis par le bootstrapper d'une app non empaquetée).
// Le paquet Main s'appelle WinAppRuntime, pas WindowsAppRuntime. L'installeur est élevé :
// Get-AppxPackage seul ne voit pas toujours les paquets de l'utilisateur, d'où -AllUsers en repli.
function IsWindowsAppRuntimeInstalled(): Boolean;
var
  ResultCode: Integer;
  Arch, Params: string;
begin
  if IsWin64 then
    Arch := 'X64'
  else
    Arch := 'X86';
  Params := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' +
    '$arch = ''' + Arch + '''; ' +
    'function Test-Pkg([string]$n) { ' +
    '  $p = @(Get-AppxPackage -Name $n -ErrorAction SilentlyContinue | Where-Object { $_.Architecture -eq $arch }); ' +
    '  if (-not $p) { try { $p = @(Get-AppxPackage -AllUsers -Name $n -ErrorAction SilentlyContinue | Where-Object { $_.Architecture -eq $arch }) } catch {} }; ' +
    '  return [bool]$p }; ' +
    'if ((Test-Pkg ''Microsoft.WindowsAppRuntime.{#WinAppRuntimeVersion}'') -and (Test-Pkg ''MicrosoftCorporationII.WinAppRuntime.Main.{#WinAppRuntimeVersion}'')) { exit 0 } else { exit 1 }"';
  Result := Exec(ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe'), Params, '',
    SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

function DotNetInstallerName(): string;
begin
  Result := 'windowsdesktop-runtime-8-win-' + ArchSuffix() + '.exe';
end;

function WinAppRuntimeInstallerName(): string;
begin
  Result := 'WindowsAppRuntimeInstall-' + ArchSuffix() + '.exe';
end;

function InitializeSetup(): Boolean;
var
  Missing, Msg: string;
begin
  Result := True;
  NeedDotNet := False;
  NeedWinAppRuntime := False;

#ifndef SelfContainedPublish
  NeedDotNet := not IsDotNet10DesktopInstalled();
#endif
#ifndef WinAppSdkSelfContainedPublish
  NeedWinAppRuntime := not IsWindowsAppRuntimeInstalled();
#endif

  if not (NeedDotNet or NeedWinAppRuntime) then
    Exit;

  Missing := '';
  if NeedDotNet then
    Missing := Missing + '  • .NET 10 Desktop Runtime' + #13#10;
  if NeedWinAppRuntime then
    Missing := Missing + '  • Windows App Runtime {#WinAppRuntimeVersion}' + #13#10;

  if ActiveLanguage = 'english' then
    Msg := 'optiSCAN needs the following Microsoft components, which are missing on this computer:' + #13#10 + #13#10 +
      Missing + #13#10 +
      'Download and install them automatically now (Internet connection required)?'
  else
    Msg := 'optiSCAN a besoin des composants Microsoft suivants, absents de cet ordinateur :' + #13#10 + #13#10 +
      Missing + #13#10 +
      'Les télécharger et les installer automatiquement maintenant (connexion Internet requise) ?';

  // Installation silencieuse (/SILENT, /VERYSILENT) : réponse « Oui » par défaut.
  if SuppressibleMsgBox(Msg, mbConfirmation, MB_YESNO, IDYES) <> IDYES then
    Result := False;
end;

function OnPrereqDownloadProgress(const Url, FileName: String; const Progress, ProgressMax: Int64): Boolean;
begin
  Result := True;
end;

procedure InitializeWizard();
begin
  PrereqDownloadPage := CreateDownloadPage(SetupMessage(msgWizardPreparing),
    SetupMessage(msgPreparingDesc), @OnPrereqDownloadProgress);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID <> wpReady) or not (NeedDotNet or NeedWinAppRuntime) then
    Exit;

  PrereqDownloadPage.Clear;
  if NeedDotNet then
    PrereqDownloadPage.Add('https://aka.ms/dotnet/10.0/windowsdesktop-runtime-win-' + ArchSuffix() + '.exe',
      DotNetInstallerName(), '');
  if NeedWinAppRuntime then
    PrereqDownloadPage.Add('https://aka.ms/windowsappsdk/{#WinAppRuntimeVersion}/latest/windowsappruntimeinstall-' + ArchSuffix() + '.exe',
      WinAppRuntimeInstallerName(), '');
  PrereqDownloadPage.Show;
  try
    try
      PrereqDownloadPage.Download;
    except
      if not PrereqDownloadPage.AbortedByUser then
        SuppressibleMsgBox(AddPeriod(GetExceptionMessage), mbCriticalError, MB_OK, IDOK);
      Result := False;
    end;
  finally
    PrereqDownloadPage.Hide;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';

  if NeedDotNet then
  begin
    // 3010 = succès, redémarrage requis ; 1638 = version égale/plus récente déjà présente.
    if not Exec(ExpandConstant('{tmp}\' + DotNetInstallerName()), '/install /quiet /norestart', '',
         SW_HIDE, ewWaitUntilTerminated, ResultCode)
       or not ((ResultCode = 0) or (ResultCode = 3010) or (ResultCode = 1638)) then
    begin
      Result := '.NET 10 Desktop Runtime : installation échouée / installation failed (code ' + IntToStr(ResultCode) + ').';
      Exit;
    end;
    if ResultCode = 3010 then
      NeedsRestart := True;
  end;

  if NeedWinAppRuntime then
  begin
    if not Exec(ExpandConstant('{tmp}\' + WinAppRuntimeInstallerName()), '--quiet', '',
         SW_HIDE, ewWaitUntilTerminated, ResultCode)
       or (ResultCode <> 0) then
    begin
      Result := 'Windows App Runtime {#WinAppRuntimeVersion} : installation échouée / installation failed (code ' + IntToStr(ResultCode) + ').';
      Exit;
    end;
  end;
end;

procedure DisablePlatformServiceTask();
var
  I: Integer;
  ItemText: string;
begin
  for I := 0 to WizardForm.TasksList.Items.Count - 1 do
  begin
    ItemText := LowerCase(WizardForm.TasksList.Items[I]);
    if (Pos('service windows de protection système', ItemText) > 0)
      or (Pos('windows system protection service', ItemText) > 0)
      or (Pos('protection système avancée', ItemText) > 0)
      or (Pos('system protection v1', ItemText) > 0) then
    begin
      WizardForm.TasksList.ItemEnabled[I] := False;
      WizardForm.TasksList.Checked[I] := False;
    end;
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpSelectTasks then
    DisablePlatformServiceTask();
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
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\*\shell', 'ScanWithOptiSCAN');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\*\shell', 'Shell_ScanWith');

  RemoveExplorerShellMenu(HKCU, 'Software\Classes\Directory\shell', 'optiSCAN.Scan');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\Directory\shell', 'Scanner avec optiSCAN');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\Directory\shell', 'Scan with optiSCAN');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\Directory\shell', 'ScanWithOptiSCAN');
  RemoveExplorerShellMenu(HKCU, 'Software\Classes\Directory\shell', 'Shell_ScanWith');

  RemoveExplorerShellMenu(HKCR, '*\shell', 'optiSCAN.Scan');
  RemoveExplorerShellMenu(HKCR, '*\shell', 'Scanner avec optiSCAN');
  RemoveExplorerShellMenu(HKCR, '*\shell', 'Scan with optiSCAN');
  RemoveExplorerShellMenu(HKCR, '*\shell', 'ScanWithOptiSCAN');
  RemoveExplorerShellMenu(HKCR, '*\shell', 'Shell_ScanWith');

  RemoveExplorerShellMenu(HKCR, 'Directory\shell', 'optiSCAN.Scan');
  RemoveExplorerShellMenu(HKCR, 'Directory\shell', 'Scanner avec optiSCAN');
  RemoveExplorerShellMenu(HKCR, 'Directory\shell', 'Scan with optiSCAN');
  RemoveExplorerShellMenu(HKCR, 'Directory\shell', 'ScanWithOptiSCAN');
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
  Exec('sc.exe', 'stop optiSCANProtection', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('sc.exe', 'delete optiSCANProtection', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('sc.exe', 'stop optiSCANProtectionV9', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('sc.exe', 'delete optiSCANProtectionV9', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('sc.exe', 'stop optiSCANProtectionV1', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('sc.exe', 'delete optiSCANProtectionV1', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
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
    // Exclusions Defender : opt-in depuis l'application (Options), non appliquées à l'installation.
    if IsTaskSelected('platformservice') then
    begin
      if ActiveLanguage = 'english' then
        MsgBox(
          'The Windows system protection service is not available in this version.' + #13#10 +
          'It is planned in 3 to 5 years (signed kernel driver required).' + #13#10 + #13#10 +
          'Application real-time protection stays active.',
          mbInformation, MB_OK)
      else
        MsgBox(
          'Le service Windows de protection système n''est pas disponible dans cette version.' + #13#10 +
          'Il est prévu dans 3 à 5 ans (pilote noyau signé requis).' + #13#10 + #13#10 +
          'La protection temps réel de l''application reste active.',
          mbInformation, MB_OK);
    end;

    { ── Installation service / minifilter : conservé pour phase 2 (pilote signé).
       Réactiver quand PlatformProtectionFeatureGate.IsUserActivatable = true. }
    if False and IsTaskSelected('platformservice') then
    begin
      if FileExists(ExpandConstant('{app}\optiSCAN.Service.exe')) then
      begin
        Exec('sc.exe', 'create optiSCANProtection binPath= "\"' + ExpandConstant('{app}\optiSCAN.Service.exe') + '\"" start= auto DisplayName= "optiSCAN Protection"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        Exec('sc.exe', 'description optiSCANProtection "Moteur de protection optiSCAN (temps réel, AMSI, IPC)"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        Exec('sc.exe', 'start optiSCANProtection', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      end
      else if ActiveLanguage = 'english' then
        MsgBox('The system protection service (optiSCAN.Service.exe) was not included in this build. Real-time protection (RTP/AMSI/IPC) will be unavailable.', mbInformation, MB_OK)
      else
        MsgBox('Le service de protection système (optiSCAN.Service.exe) n''est pas inclus dans cette version. La protection temps réel (RTP/AMSI/IPC) sera indisponible.', mbInformation, MB_OK);

      if not FileExists(ExpandConstant('{app}\optiSCAN.Minifilter.sys')) then
      begin
        if ActiveLanguage = 'english' then
          MsgBox('Note: the kernel minifilter driver (optiSCAN.Minifilter.sys) is absent or unsigned. Kernel-level real-time protection will not load on 64-bit Windows without a properly signed driver.', mbInformation, MB_OK)
        else
          MsgBox('Note : le pilote minifiltre noyau (optiSCAN.Minifilter.sys) est absent ou non signé. La protection temps réel au niveau noyau ne se chargera pas sous Windows 64 bits sans pilote signé.', mbInformation, MB_OK);
      end;
    end;
  end;

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
