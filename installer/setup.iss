; SPDX-License-Identifier: GPL-3.0-or-later
; =============================================================================
; optiSCAN — Installateur Windows (Inno Setup)
; =============================================================================
; AppRelease = nom vM.m (v3.1) · AppVersion = semver / Directory.Build.props

#define AppName        "optiSCAN"
#ifndef AppVersion
#define AppVersion     "3.1.0-beta.1"
#endif
; VersionInfo* n'accepte que des chiffres : on retire le suffixe de pré-version (-beta.1).
#define AppNumericVersion Copy(AppVersion, 1, Pos("-", AppVersion + "-") - 1)
#ifndef AppRelease
#define AppRelease     "v3.1"
#endif
#define AppPublisher   "Dona By"
#define AppURL         "https://sourceforge.net/projects/optiscan/"
#define AppExeName     "optiSCAN.exe"
#define AppId          "{{F3A2C1D0-5B6E-4F7A-8C9D-0E1F2A3B4C5D}"
#define AppIconFile    "..\optiSCAN\optiSCAN.ico"

#include "protection_identifiers.iss"

; ── ISPP : emplacement de publish (VS / dotnet peuvent sortir dans publish\win-x64\ ou publish\)
; Préférer win-x64 en premier : c'est la sortie d'un « dotnet publish -r win-x64 » / profil dossier,
; et un vieux optiSCAN.exe à la racine de publish\ ne doit pas masquer une publication RID récente.
; Le .csproj supprime win-x64 / win-x86 / publish avant chaque publish (cible CleanStalePublishOutput).
; CI : /DAppPublishSource=..\publish\win-x64\*
#ifndef AppPublishSource
#if FileExists(AddBackslash(SourcePath) + "..\optiSCAN\bin\Release\net10.0-windows10.0.17763.0\publish\win-x64\optiSCAN.exe")
  #define AppPublishSource "..\optiSCAN\bin\Release\net10.0-windows10.0.17763.0\publish\win-x64\*"
#elif FileExists(AddBackslash(SourcePath) + "..\optiSCAN\bin\Release\net10.0-windows10.0.17763.0\publish\optiSCAN.exe")
  #define AppPublishSource "..\optiSCAN\bin\Release\net10.0-windows10.0.17763.0\publish\*"
#else
  #expr Error("optiSCAN.exe introuvable. Ouvrez optiSCAN.csproj puis menu Build > Publish (Release), ou en ligne de commande : dotnet publish -c Release -r win-x64")
#endif
#endif

; ── Contrôle du service à la compilation ────────────────────────────────────
; Sans optiSCAN.Service.dll dans le dossier publié, l'installeur livrerait un service qui ne
; démarre pas (ou pas de service du tout). /DAllowMissingService pour un build de développement.
#define AppPublishDir Copy(AppPublishSource, 1, Len(AppPublishSource) - 1)
; Fournisseur AMSI : exigé pour une release ; /DAllowMissingAmsi pour un build local sans C++.
#if FileExists(AppPublishDir + "optiSCAN.AmsiProvider.dll") || FileExists(AddBackslash(SourcePath) + AppPublishDir + "optiSCAN.AmsiProvider.dll")
  #define HaveAmsiProvider
#else
  #ifndef AllowMissingAmsi
    #error optiSCAN.AmsiProvider.dll absent du dossier publié : scripts\build-amsi.ps1 puis scripts\stage-amsi.ps1, ou compiler avec /DAllowMissingAmsi.
  #endif
#endif

#ifndef AllowMissingService
#if !FileExists(AppPublishDir + "optiSCAN.Host.dll") && !FileExists(AddBackslash(SourcePath) + AppPublishDir + "optiSCAN.Host.dll")
  #error optiSCAN.Host.dll absent du dossier publié : l'hôte SYSTEM (optiSCAN.Host) doit être publié dans le même dossier (publish-release.ps1), ou compiler avec /DAllowMissingService.
#endif
#if !FileExists(AppPublishDir + "optiSCAN.Service.dll") && !FileExists(AddBackslash(SourcePath) + AppPublishDir + "optiSCAN.Service.dll")
  #error optiSCAN.Service.dll absent du dossier publié : publier optiSCAN.Service dans le même dossier que optiSCAN (scripts\prepare-release-v3.ps1 ou publish-release.ps1), ou compiler avec /DAllowMissingService.
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
; Même AppId que les versions 1 et 2 : installation par-dessus, même dossier.
UsePreviousAppDir=yes
; Le service SYSTEM et l'hôte de protection s'exécutent depuis {app} : ce dossier doit être
; réservé aux administrateurs. Seul Program Files le garantit (un dossier créé à la racine d'un
; volume hérite d'un droit de modification pour les utilisateurs authentifiés). Le choix du
; dossier est donc fermé, et PrepareToInstall refuse aussi un /DIR= ou un ancien dossier.
DisableDirPage=yes
DisableProgramGroupPage=auto
; Pas d'AppMutex ici : il bloquerait l'assistant tant qu'une version
; déjà lancée tient Global\optiSCAN_UniqueInstance. StopRunningOptiScan la ferme.
CloseApplications=force
CloseApplicationsFilter=optiSCAN.exe,optiSCAN.Service.exe,optiSCAN.Host.exe
RestartApplications=no
VersionInfoVersion={#AppNumericVersion}
VersionInfoTextVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} — Installateur
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppNumericVersion}
VersionInfoProductTextVersion={#AppVersion}
VersionInfoCopyright=Copyright 2026 Dona By

; ── SIGNATURE DE CODE ───────────────────────────────────────────────────────
; Une seule chaîne : SignPath Foundation, dans .github/workflows/release.yml.
; Les binaires publiés sont signés avant la compilation de l'installeur, puis
; l'installeur compilé est signé à son tour. Aucun certificat ni mot de passe
; n'existe sur un poste ou dans les secrets du dépôt (docs/CODE_SIGNING_POLICY.md).

; Langue de l'installateur = langue de l'application (UiCulture en Registre).
ShowLanguageDialog=auto

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
; Profil d'install allégé façon v2 : défaut = UI + ClamAV + YARA (+ MAJ signatures).
; Service de protection : coché à la première installation (checkedonce) pour que la
; protection survive à la fermeture de session ; une mise à jour garde le choix précédent.
; Libellés par langue ([CustomMessages]) : l'installeur anglais les affichait en français.
Name: "desktopicon";   Description: "{cm:TaskDesktopIcon}";     GroupDescription: "{cm:GroupIcons}"
Name: "startupicon";   Description: "{cm:TaskStartup}";         GroupDescription: "{cm:GroupAdvanced}"; Flags: unchecked
Name: "autoUpdateSig"; Description: "{cm:TaskAutoUpdateSig}";   GroupDescription: "{cm:GroupEngines}"; Flags: checkedonce
Name: "platformservice"; Description: "{cm:TaskPlatformService}"; GroupDescription: "{cm:GroupProtection}"; Flags: checkedonce

[CustomMessages]
french.TaskDesktopIcon=Créer une icône sur le Bureau
english.TaskDesktopIcon=Create a desktop shortcut
french.GroupIcons=Icônes supplémentaires
english.GroupIcons=Additional shortcuts
french.TaskStartup=Lancer optiSCAN au démarrage de Windows
english.TaskStartup=Start optiSCAN when Windows starts
french.GroupAdvanced=Options avancées
english.GroupAdvanced=Advanced options
french.TaskAutoUpdateSig=Activer les mises à jour auto des signatures (recommandé)
english.TaskAutoUpdateSig=Enable automatic signature updates (recommended)
french.GroupEngines=Moteurs ClamAV + YARA
english.GroupEngines=ClamAV + YARA engines
french.TaskPlatformService=Installer le service Windows de protection (temps réel hors session, recommandé)
english.TaskPlatformService=Install the Windows protection service (real-time outside your session, recommended)
french.GroupProtection=Protection
english.GroupProtection=Protection
french.LaunchNow=Lancer %1 maintenant
english.LaunchNow=Launch %1 now

[Files]
; ── Application principale ───────────────────────────────────────────────────
; Avant de compiler : Build > Publish (Release) ou : dotnet publish -c Release
; Le chemin exact est résolu par le préprocesseur (AppPublishSource).
; clamav\*, rules\* et yara\* sont exclus ici — gérés séparément ci-dessous.
Source: "{#AppPublishSource}"; DestDir: "{app}"; Excludes: "clamav\*,rules\*,yara\*,bin\*,*.pdb,optiSCAN.AmsiProvider.dll"; Flags: ignoreversion recursesubdirs createallsubdirs
; ── Fournisseur AMSI (analyse des scripts avant exécution) ─────────────────────
; Enregistré avec le service (son seul serveur) : DllRegisterServer écrit la classe COM et
; l'entrée HKLM\SOFTWARE\Microsoft\AMSI\Providers ; la désinstallation les retire.
; restartreplace : une mise à jour remplace la DLL au redémarrage si un processus la charge.
#ifdef HaveAmsiProvider
Source: "{#AppPublishDir}optiSCAN.AmsiProvider.dll"; DestDir: "{app}"; Tasks: platformservice; Flags: ignoreversion regserver 64bit restartreplace uninsrestartdelete
#endif
; ── ClamAV x64 — outils développeur exclus (sigtool/clambc & co : ~47 Mo
; inutiles au scan et à la mise à jour ; le code n'y fait jamais appel) ──────
; UnRAR (libclamunrar*, COPYING.unrar) n'est pas sous licence libre : jamais livré.
#if DirExists(AddBackslash(SourcePath) + "..\optiSCAN\clamav\x64")
Source: "..\optiSCAN\clamav\x64\*"; DestDir: "{app}\clamav\x64"; Excludes: "sigtool.exe,clambc.exe,clamdtop.exe,clamsubmit.exe,clamconf.exe,*unrar*"; Flags: ignoreversion recursesubdirs createallsubdirs
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
; après installation (réseau requis au 1er lancement). Aligné setup v2 léger.
; Offline : /DEmbedClamAvDatabase ou /DEmbedOfflineSignatures
#ifdef EmbedClamAvDatabase
Source: "..\optiSCAN\clamav\database\*"; DestDir: "{app}\clamav\database"; Excludes: "*.log"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
#endif
; ── YARA : binaire et règles locales. YARA-Forge les complète dans le dossier inscriptible.
Source: "..\optiSCAN\rules\*"; DestDir: "{app}\rules"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
Source: "..\optiSCAN\yara\*"; DestDir: "{app}\yara"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
; ── Licences des composants tiers (YARA, avis généraux). Celles de ClamAV arrivent avec
; clamav\x64\licenses (fetch-runtime-deps.ps1) ; l'installeur refuse de se compiler sans elles.
Source: "licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion
#if !FileExists(AddBackslash(SourcePath) + "..\optiSCAN\clamav\x64\licenses\COPYING.txt")
  #error Licence ClamAV absente (optiSCAN\clamav\x64\licenses\COPYING.txt) : relancer scripts\fetch-runtime-deps.ps1.
#endif
; ── Service Windows (tâche platformservice, cochée par défaut) ───────────────────────
; optiSCAN.Service.exe, sa DLL et ses dépendances arrivent par AppPublishSource : le service est
; publié dans le même dossier que l'application (CI, prepare-release-v3, publish-release).
; Un exe copié seul ne démarre pas ; la présence de la DLL est vérifiée plus haut à la compilation.
; Script exclusions Defender : copié pour usage manuel / depuis l'app — PAS exécuté
; automatiquement à l'install (évite le marqueur heuristique « tamper » post-v2).
Source: "..\scripts\add-defender-exclusions.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion
; Minifiltre : non livré (prototype sous native/, ni compilé ni copié). Le fournisseur AMSI,
; lui, est livré avec le service (voir plus haut).
[Dirs]
; Propriétaire administrateur : un utilisateur ne peut pas préparer une jonction avant le service.
Name: "{commonappdata}\optiSCAN"; Permissions: admins-full system-full

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: startupicon

; HKCU est écrit dans CurStepChanged via ExecAsOriginalUser, pas dans le profil de l'administrateur élevé.

[Run]
; Lancé avec le jeton de l'utilisateur qui a démarré l'installation, pas celui de l'installeur
; élevé : une instance élevée refuse freshclam et winget (configuration dans le profil, modifiable
; sans élévation) et écrirait ses données dans le profil de l'administrateur.
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchNow,{#AppName}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

; =============================================================================
; CLEAN INSTALL — exécuté AVANT la copie des nouveaux fichiers
; =============================================================================
; Supprime les fichiers de configuration legacy susceptibles de contenir des
; chemins de la machine de dev ou la directive CVDCertsDirectory cassée
; (héritée des versions antérieures). Le code optiSCAN regénère un freshclam.conf
; propre dans %LocalAppData% au premier lancement de la mise à jour.
[InstallDelete]
; --- Raccourci de désinstallation des versions antérieures (nom figé en français) ---
Type: files; Name: "{group}\Désinstaller {#AppName}.lnk"

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

; --- UnRAR livré par les versions antérieures (licence non libre) ---
Type: files; Name: "{app}\clamav\x64\libclamunrar.dll"
Type: files; Name: "{app}\clamav\x64\libclamunrar_iface.dll"
Type: files; Name: "{app}\clamav\x64\licenses\COPYING.unrar"

; freshclam.conf utilisateur : nettoyé après copie, dans le profil d'origine
; (pas celui de l'administrateur qui a élevé l'installation).

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

procedure Sleep(dwMilliseconds: LongInt);
  external 'Sleep@kernel32.dll stdcall';

function OptiScanProcessStillRunning(): Boolean;
var
  WbemLocator, WbemServices, Processes: Variant;
begin
  Result := False;
  try
    WbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
    WbemServices := WbemLocator.ConnectServer('.', 'root\CIMV2');
    Processes := WbemServices.ExecQuery('SELECT ProcessId FROM Win32_Process WHERE Name="optiSCAN.exe" OR Name="optiSCAN.Service.exe" OR Name="optiSCAN.Host.exe"');
    Result := Integer(Processes.Count) > 0;
  except
    Result := False;
  end;
end;

procedure StopProtectionService(const Name: string);
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop ' + Name, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure DeleteProtectionService(const Name: string);
var
  ResultCode: Integer;
begin
  StopProtectionService(Name);
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete ' + Name, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure InstallCurrentProtectionService();
var
  ResultCode: Integer;
  BinPathArg: string;
begin
  if not FileExists(ExpandConstant('{app}\optiSCAN.Service.exe')) then
  begin
    if ActiveLanguage = 'english' then
      MsgBox('The system protection service (optiSCAN.Service.exe) was not included in this build. Real-time protection will be unavailable.', mbInformation, MB_OK)
    else
      MsgBox('Le service de protection système (optiSCAN.Service.exe) n''est pas inclus dans cette version. La protection temps réel sera indisponible.', mbInformation, MB_OK);
    Exit;
  end;

  BinPathArg := 'binPath= "\"' + ExpandConstant('{app}\optiSCAN.Service.exe') + '\""';
  if not Exec(ExpandConstant('{sys}\sc.exe'), 'create {#ProtectionServiceName} ' + BinPathArg + ' start= auto DisplayName= "{#ProtectionServiceDisplayName}"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;

  // 1073 : le service existe déjà (mise à jour). StopRunningOptiScan l'a arrêté : sans ce cas,
  // l'installeur affichait une erreur et le laissait arrêté jusqu'au prochain redémarrage.
  if ResultCode = 1073 then
  begin
    if not Exec(ExpandConstant('{sys}\sc.exe'), 'config {#ProtectionServiceName} ' + BinPathArg + ' start= auto DisplayName= "{#ProtectionServiceDisplayName}"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
       or (ResultCode <> 0) then
      Log(Format('sc config a échoué (code %d)', [ResultCode]));
    ResultCode := 0;
  end;

  if ResultCode <> 0 then
  begin
    Log(Format('sc create a échoué (code %d)', [ResultCode]));
    if ActiveLanguage = 'english' then
      SuppressibleMsgBox(Format('The protection service could not be registered (sc.exe code %d). Real-time protection will be unavailable.', [ResultCode]), mbError, MB_OK, IDOK)
    else
      SuppressibleMsgBox(Format('Le service de protection n''a pas pu être enregistré (code sc.exe %d). La protection temps réel sera indisponible.', [ResultCode]), mbError, MB_OK, IDOK);
    Exit;
  end;

  if not Exec(ExpandConstant('{sys}\sc.exe'), 'description {#ProtectionServiceName} "{#ProtectionServiceDescription}"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
     or (ResultCode <> 0) then
    Log(Format('sc description a échoué (code %d)', [ResultCode]));

  // Récupération par le gestionnaire de services : sans elle, un plantage du service, ou son
  // arrêt volontaire en erreur (StopWithError), laisse la machine sans protection jusqu'au
  // prochain redémarrage. failureflag 1 applique aussi ces actions à un arrêt avec code non nul.
  if not Exec(ExpandConstant('{sys}\sc.exe'), 'failure {#ProtectionServiceName} reset= 86400 actions= restart/5000/restart/60000/restart/300000', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
     or (ResultCode <> 0) then
    Log(Format('sc failure a échoué (code %d)', [ResultCode]));
  if not Exec(ExpandConstant('{sys}\sc.exe'), 'failureflag {#ProtectionServiceName} 1', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
     or (ResultCode <> 0) then
    Log(Format('sc failureflag a échoué (code %d)', [ResultCode]));

  // 1056 : service déjà démarré.
  if not Exec(ExpandConstant('{sys}\sc.exe'), 'start {#ProtectionServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
     or ((ResultCode <> 0) and (ResultCode <> 1056)) then
  begin
    Log(Format('sc start a échoué (code %d)', [ResultCode]));
    if ActiveLanguage = 'english' then
      SuppressibleMsgBox(Format('The protection service is registered but did not start (sc.exe code %d). See the Application event log.', [ResultCode]), mbInformation, MB_OK, IDOK)
    else
      SuppressibleMsgBox(Format('Le service de protection est enregistré mais n''a pas démarré (code sc.exe %d). Voir le journal Application.', [ResultCode]), mbInformation, MB_OK, IDOK);
  end;
end;

// Le service et l'hôte SYSTEM s'exécutent depuis {app} : refuser tout dossier hors de
// Program Files (paramètre /DIR=, ou dossier d'une installation antérieure).
function InstallDirIsUnderProgramFiles(): Boolean;
var
  Dir, ProgramFiles: string;
begin
  Dir := Lowercase(AddBackslash(WizardDirValue()));
  ProgramFiles := Lowercase(AddBackslash(ExpandConstant('{autopf}')));
  Result := (Pos(ProgramFiles, Dir) = 1) and (Length(Dir) > Length(ProgramFiles));
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if not InstallDirIsUnderProgramFiles() then
  begin
    if ActiveLanguage = 'english' then
      Result := 'optiSCAN must be installed under ' + ExpandConstant('{autopf}') + ': its system service runs from the installation folder, '
        + 'which must be writable by administrators only. Uninstall the copy located in ' + WizardDirValue() + ', then run this installer again.'
    else
      Result := 'optiSCAN doit être installé sous ' + ExpandConstant('{autopf}') + ' : son service système s''exécute depuis le dossier d''installation, '
        + 'qui doit être modifiable par les seuls administrateurs. Désinstallez la copie située dans ' + WizardDirValue() + ', puis relancez cet installateur.';
  end;
end;

procedure StopRunningOptiScan();
var
  ResultCode, Attempt: Integer;
begin
  StopProtectionService('{#ProtectionServiceName}');
  for Attempt := 1 to 15 do
  begin
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM optiSCAN.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM optiSCAN.Service.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    // Hôte SYSTEM depuis 3.1 : resté vivant, il verrouille ses DLL et la copie échoue.
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM optiSCAN.Host.exe /T', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if not OptiScanProcessStillRunning() then
      Break;
    Sleep(200);
  end;
  Sleep(400);
end;

function InitializeSetup(): Boolean;
begin
  StopRunningOptiScan();
  Result := True;
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

  Exec(ExpandConstant('{app}\{#AppExeName}'), '--remove-defender-exclusions --quiet', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "optiSCAN_DailyScan" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/Delete /TN "optiSCAN_Watchdog" /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  Exec(ExpandConstant('{sys}\fltmc.exe'), 'unload optiSCANMinifilter', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  DeleteProtectionService('{#ProtectionServiceName}');

  if RegKeyExists(HKLM, 'SOFTWARE\Microsoft\AMSI\Providers\{A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}') then
    RegDeleteKeyIncludingSubkeys(HKLM, 'SOFTWARE\Microsoft\AMSI\Providers\{A8F4E2B1-9C3D-4E5F-8A7B-1C2D3E4F5A6B}');

  // Marqueurs machine (nettoyage des exclusions 3.0.0, essais historique Defender).
  if RegKeyExists(HKLM, 'SOFTWARE\optiSCAN') then
    RegDeleteKeyIncludingSubkeys(HKLM, 'SOFTWARE\optiSCAN');

  // Données machine, dont la quarantaine du service (ProgramData\optiSCAN\Quarantine) :
  // sa clé est protégée au nom de SYSTEM, elle n'est plus lisible une fois le service retiré.
  if DirExists(ExpandConstant('{commonappdata}\optiSCAN')) then
    DelTree(ExpandConstant('{commonappdata}\optiSCAN'), True, True, True);

  // Données du service dans le profil SYSTEM : journaux, réglages, et quarantaine des
  // versions 3.0.x si aucun démarrage du service ne l'a déplacée vers ProgramData.
  if DirExists(ExpandConstant('{sys}\config\systemprofile\AppData\Local\optiSCAN')) then
    DelTree(ExpandConstant('{sys}\config\systemprofile\AppData\Local\optiSCAN'), True, True, True);
end;

function InitializeUninstall(): Boolean;
begin
  { Ne rien démonter ici : Annuler doit laisser le produit intact.
    Le retrait a lieu dans CurUninstallStepChanged(usUninstall). }
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
procedure WriteOriginalUserReg(const Args: string);
var
  ResultCode: Integer;
begin
  ExecAsOriginalUser(ExpandConstant('{sys}\reg.exe'), Args, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure WriteInstallerUiCulture();
var
  Culture: string;
begin
  if ActiveLanguage = 'english' then
    Culture := 'en-US'
  else
    Culture := 'fr-FR';
  WriteOriginalUserReg('add "HKCU\Software\optiSCAN" /v UiCulture /t REG_SZ /d "' + Culture + '" /f');
  WriteOriginalUserReg('add "HKCU\Software\optiSCAN" /v Version /t REG_SZ /d "{#AppVersion}" /f');
  if WizardIsTaskSelected('autoUpdateSig') then
    WriteOriginalUserReg('add "HKCU\Software\optiSCAN" /v AutoUpdateSignatures /t REG_DWORD /d 1 /f');
end;

procedure RegisterExplorerContextMenu();
var
  MenuKey, MenuLabel, ExePath: string;
begin
  if ActiveLanguage = 'english' then
    MenuLabel := 'Scan with optiSCAN'
  else
    MenuLabel := 'Scanner avec optiSCAN';

  MenuKey := 'optiSCAN.Scan';
  ExePath := ExpandConstant('{app}\{#AppExeName}');

  UnregisterExplorerContextMenus();

  WriteOriginalUserReg('add "HKCU\Software\Classes\*\shell\' + MenuKey + '" /ve /d "' + MenuLabel + '" /f');
  WriteOriginalUserReg('add "HKCU\Software\Classes\*\shell\' + MenuKey + '" /v Icon /d "' + ExePath + ',0" /f');
  WriteOriginalUserReg('add "HKCU\Software\Classes\*\shell\' + MenuKey + '\command" /ve /d "\"' + ExePath + '\" --scan \"%1\"" /f');

  WriteOriginalUserReg('add "HKCU\Software\Classes\Directory\shell\' + MenuKey + '" /ve /d "' + MenuLabel + '" /f');
  WriteOriginalUserReg('add "HKCU\Software\Classes\Directory\shell\' + MenuKey + '" /v Icon /d "' + ExePath + ',0" /f');
  WriteOriginalUserReg('add "HKCU\Software\Classes\Directory\shell\' + MenuKey + '\command" /ve /d "\"' + ExePath + '\" --scan \"%1\"" /f');
end;

// Exclusions Defender : volontairement NON appelées ici (profil allégé v2).
// Le script reste dans {app}\scripts pour un opt-in depuis l'application.

procedure ResetOriginalUserFreshclamConf();
var
  ResultCode: Integer;
begin
  ExecAsOriginalUser(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -Command "& { $p = Join-Path $env:LOCALAPPDATA ''optiSCAN\clamav\freshclam.conf''; if (Test-Path -LiteralPath $p) { $b = [IO.File]::ReadAllBytes($p); $t = [Text.Encoding]::UTF8.GetString($b); $bom = ($b.Length -ge 3 -and $b[0] -eq 239 -and $b[1] -eq 187 -and $b[2] -eq 191); if ($bom -or $t.Contains(''CVDCertsDirectory'')) { Remove-Item -LiteralPath $p -Force } } }"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CleanupLegacyDefenderExclusions();
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{app}\{#AppExeName}'), '--cleanup-legacy-defender-exclusions --quiet', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    WriteInstallerUiCulture();
    RegisterExplorerContextMenu();
    ResetOriginalUserFreshclamConf();
    // Mise à jour depuis 3.0.0 : retirer les exclusions Defender par simple nom
    // et sur AppData\Local\optiSCAN, que l'ancienne version posait.
    CleanupLegacyDefenderExclusions();
    // Installation neuve : la case « protection avancée » reste décochée.
    if WizardIsTaskSelected('platformservice') then
      InstallCurrentProtectionService();
  end;

  if CurStep = ssInstall then
    StopRunningOptiScan();
end;
