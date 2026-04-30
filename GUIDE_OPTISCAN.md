# Guide Complet — optiSCAN v1.0

> **Version de référence.** Ce guide décrit l'architecture, les modules et les procédures
> de la version 1.0 du produit. Architecture mono-fenêtre — plus de ScanWindow séparée.

---

## 1. Architecture technique

### Choix du langage : C# WPF .NET 8

| Critère | WPF | MAUI | C++ natif |
|---|---|---|---|
| Compatibilité Windows | ✅ Natif | ⚠ Multi-plateforme (overhead) | ✅ Natif |
| Intégration ClamAV | ✅ Process.Start | ✅ Process.Start | ✅ libclamav directe |
| MVVM + Binding UI | ✅ Excellent | ⚠ Différent | ❌ Manuel |
| **Verdict** | **✅ Retenu** | Non nécessaire | Non nécessaire |

---

### Structure des modules

```
optiSCAN/
├── optiSCAN/                          ← Solution Visual Studio
│   ├── GUIDE_OPTISCAN.md              ← Ce fichier
│   ├── installer/
│   │   └── setup.iss                  ← Script Inno Setup
│   └── optiSCAN/                      ← Projet C# WPF
│       ├── Models/
│       │   ├── ThreatInfo.cs          ← Menace détectée
│       │   ├── ScanProgress.cs        ← Progression temps réel (IProgress<T>)
│       │   ├── ScanResult.cs          ← Résultat global d'un scan
│       │   └── ScanSession.cs         ← Entrée d'historique (persistable JSON)
│       │
│       ├── Services/
│       │   ├── ClamAvEngine.cs        ← Lance clamscan.exe, parse la sortie
│       │   ├── FreshclamUpdater.cs    ← Mise à jour signatures via freshclam.exe
│       │   ├── ExclusionSettings.cs   ← Dossiers et règles exclus (singleton JSON)
│       │   ├── YaraEngine.cs          ← Moteur de détection comportementale
│       │   ├── YaraForgeUpdater.cs    ← Mise à jour automatique règles de détection
│       │   ├── ScanOrchestrator.cs    ← Pipeline ClamAV + détection en parallèle
│       │   ├── QuarantineManager.cs   ← Déplace/restaure/supprime les fichiers infectés
│       │   └── ScanLogManager.cs      ← Historique JSON + journal texte
│       │
│       ├── MainWindow.xaml            ← Fenêtre unique — 5 panneaux sidebar
│       ├── MainWindow.xaml.cs         ← Code-behind complet (nettoyage + antivirus)
│       ├── yara/                      ← Binaires du moteur de détection
│       │   ├── yara64.exe
│       │   ├── yara32.exe
│       │   ├── yarac64.exe
│       │   └── yarac32.exe
│       ├── rules/                     ← Règles de détection (.yar)
│       │   ├── malware_signatures.yar
│       │   ├── suspicious_strings.yar
│       │   └── _compiled.yarc         ← Cache compilé (regénéré automatiquement)
│       └── clamav/                    ← Binaires et base ClamAV
│           ├── x64/                   ← Binaires Windows x86-64 (pas ARM64 !)
│           ├── x86/
│           └── database/
```

> **Note v1.0 :** `Views/ScanWindow.xaml` et `Views/ScanWindow.xaml.cs` ont été supprimés.
> Toute la logique antivirus est intégrée dans `MainWindow` (panneau Antivirus, index 4).
> `ViewModels/ScanViewModel.cs` peut également être supprimé — il n'est plus référencé.

**Règle de séparation :**
- `Models/` — aucune dépendance UI, testable en console
- `Services/` — aucune dépendance UI, injectables
- `MainWindow.xaml.cs` — orchestre tous les services, met à jour l'UI directement

---

## 2. Installation et configuration de ClamAV

### 2.1 Télécharger ClamAV (version x86-64 obligatoire)

```
https://www.clamav.net/downloads#otherversions
→ Windows → clamav-X.Y.Z.win.x64.zip   ← ZIP, pas MSI, pas ARM64
```

> ⚠ La version `win.arm64` cause l'erreur `0xc000007b` sur les machines Intel/AMD.

### 2.2 Placer les binaires dans le projet

```
optiSCAN/optiSCAN/clamav/x64/
    ├── clamscan.exe
    ├── freshclam.exe
    ├── libclamav.dll
    ├── libclammspack.dll      ← obligatoire
    ├── libclamunrar.dll
    ├── freshclam.conf
    └── database/              ← rempli par freshclam
```

### 2.3 Première mise à jour des signatures

```powershell
.\clamav\x64\freshclam.exe --datadir=".\clamav\x64\database"
```

Télécharge : `main.cvd` (~170 Mo), `daily.cvd` (~60 Mo), `bytecode.cvd` (~200 Ko).

### 2.4 Codes de sortie clamscan

| Code | Signification |
|---|---|
| 0 | Aucune menace |
| 1 | Menace(s) détectée(s) |
| 2 | Erreur de scan |

---

## 3. Architecture mono-fenêtre (v1.0)

### 3.1 Les 5 panneaux de MainWindow

| Index | Panneau | Contenu |
|---|---|---|
| 0 | Vue d'ensemble | Cartes résumé (espace, antivirus, historique, MAJ) |
| 1 | Nettoyer | Analyse + suppression des fichiers temporaires |
| 2 | Historique | Liste des scans passés |
| 3 | Options | Général, ClamAV, Exclusions, À propos |
| 4 | Antivirus | Scan, Quarantaine, Historique, Signatures |

Navigation via `ShowPanel(index)` — visibilité XAML gérée par `Visibility="Collapsed"`.

### 3.2 Panneau Antivirus (index 4)

Panneau divisé en deux colonnes :
- **Colonne gauche (210px)** : boutons de scan + statistiques en temps réel
- **Colonne droite** : TabControl avec 4 onglets :
  - **Scan en cours** — progression, liste des menaces, quarantaine globale
  - **Quarantaine** — fichiers mis en quarantaine, restauration/suppression unitaire
  - **Historique** — tous les scans enregistrés (horodatés)
  - **Signatures** — version base ClamAV, MAJ manuelle, logs freshclam

### 3.3 Pipeline de détection en parallèle

```
StartAntivirusScanAsync(type, path?)
    │
    ├─→ ScanOrchestrator  ←→ filtre ExclusionSettings.Current
    │        ├─→ ClamAvEngine.ScanFolderAsync()    ┐
    │        └─→ YaraEngine (RunYaraOnFolder)       ┘ Task.WhenAll
    │                ↓ filtrage des règles exclues
    └─→ MergeResults() → UI mise à jour (Progress<ScanProgress>)
```

### 3.4 Mise à jour des signatures

`BtnManualUpdateSignatures_Click` lance séquentiellement :
1. `FreshclamUpdater.UpdateAsync()` — signatures ClamAV
2. `YaraForgeUpdater.UpdateAsync()` — règles de détection comportementale

Auto-update silencieux en arrière-plan :
- Signatures ClamAV : toutes les **4h**
- Règles de détection : toutes les **24h**

### 3.5 Système d'exclusions

`ExclusionSettings.Current` (singleton) persiste dans :
```
%LOCALAPPDATA%\optiSCAN\exclusions.json
```

- **Dossiers exclus** : fichiers dans ces dossiers sautés lors du scan YARA
- **Règles exclues** : matches filtrés (ex. `SuspiciousDownloads` — exclu par défaut)

Configurable depuis **Options → EXCLUSIONS**.

### 3.6 QuarantineManager — sécurité des fichiers infectés

Les fichiers en quarantaine sont **chiffrés par XOR** (`0x5A`) :
- Empêche Windows Defender de les détecter comme actifs
- Réversible (restauration = re-XOR)

Stockage : `%LOCALAPPDATA%\optiSCAN\Quarantine\`
- Fichiers : `{guid}.quar`
- Index : `manifest.json`

### 3.7 ScanLogManager — persistance

- Historique : `%LOCALAPPDATA%\optiSCAN\Logs\scan_history.json` (100 entrées max)
- Journal : `%LOCALAPPDATA%\optiSCAN\Logs\optiSCAN.log`

---

## 4. Workflow utilisateur optiSCAN v1.0

```
DÉMARRAGE
    │
    ├─→ Vérification ClamAV installé
    ├─→ Vérification base de signatures
    ├─→ Auto-update signatures      (toutes les 4h,  silencieux)
    └─→ Auto-update règles détection (toutes les 24h, silencieux)
             │
             └─→ Fenêtre principale unique
                     │
                     ├─→ [NETTOYER]    → analyse Temp + suppression avec confirmation
                     │
                     ├─→ [ANTIVIRUS]
                     │       ├─→ [⚡ Scan Rapide]     → Temp, Downloads, Bureau
                     │       ├─→ [🔍 Scan Complet]    → Tous les disques (lent)
                     │       ├─→ [📁 Scanner dossier] → FolderBrowserDialog
                     │       ├─→ [📄 Scanner fichier] → OpenFileDialog
                     │       └─→ [🧪 Test EICAR]      → Vérifie les deux moteurs
                     │               │
                     │               ↓ Pendant le scan :
                     │               ├─ ProgressBar indéterminée (visible)
                     │               ├─ Compteurs fichiers / menaces (temps réel)
                     │               └─ Bouton [⛔ Arrêter] actif
                     │               │
                     │               ↓ Fin du scan :
                     │               ├─ Résumé + dernier scan horodaté
                     │               ├─ [🛡️ Tout mettre en quarantaine]
                     │               └─ Sauvegarde automatique historique
                     │
                     ├─→ [HISTORIQUE] → tous les scans
                     └─→ [OPTIONS]    → exclusions dossiers/règles + paramètres
```

---

## 5. Bonnes pratiques

### 5.1 Permissions et droits

```xml
<!-- app.manifest — OBLIGATOIRE pour scanner C:\Windows -->
<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
```

### 5.2 Performance

| Technique | Impact |
|---|---|
| Pipeline parallèle (Task.WhenAll) | ✅ ClamAV + détection simultanés |
| Règles pré-compilées (_compiled.yarc) | ✅ Scan ~10× plus rapide |
| Scan rapide limité aux dossiers critiques | ✅ ~30 s vs 1h+ pour un scan complet |
| ExclusionSettings.Current (singleton lazy) | ✅ Pas de rechargement JSON à chaque fichier |
| Mise à jour ClamAV toutes les 4h | ✅ Signatures fraîches |
| Mise à jour règles toutes les 24h | ✅ Détection comportementale à jour |

### 5.3 Faux positifs

- `SuspiciousDownloads` exclue par défaut (trop agressive sur le dossier Downloads)
- Ne jamais supprimer automatiquement — toujours mettre en quarantaine
- L'utilisateur confirme avant toute action destructrice

### 5.4 Exclusion Windows Defender

```powershell
Add-MpPreference -ExclusionPath "C:\Program Files\optiSCAN\clamav\database"
```

---

## 6. Packaging final (v1.0)

```powershell
# 1. Compilation Release
cd optiSCAN/optiSCAN
dotnet publish -c Release -r win-x64 --self-contained false -o ..\..\build\app

# 2. Télécharger base ClamAV initiale
.\build\app\clamav\x64\freshclam.exe --datadir=".\build\app\clamav\x64\database"

# 3. Compiler l'installateur Inno Setup
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" .\installer\setup.iss
# → installer\output\optiSCAN_Setup_v1.0.exe
```

**Contenu de l'installateur (~250 Mo avec signatures initiales) :**

```
optiSCAN_Setup_v1.0.exe
    ├── optiSCAN.exe
    ├── *.dll (runtime .NET 8)
    ├── clamav/x64/          ← Binaires x86-64 + base de signatures
    ├── yara/                ← Binaires du moteur de détection
    └── rules/               ← Règles de détection initiales
```

---

## 7. Dépendances et licences

| Composant | Licence | Notes |
|---|---|---|
| ClamAV | GPLv2 | Inclure la licence dans l'installateur |
| .NET 8 WPF | MIT | Inclus dans le runtime Windows |
| MaterialDesignThemes | MIT | Bibliothèque UI (v5.3.1) |
| Inno Setup | Freeware | Gratuit pour projets commerciaux |
| Base de signatures ClamAV | ClamAV License | Mise à jour depuis database.clamav.net |
| Règles de détection | Diverses open-source | Récupérées depuis YARA-Forge |

---

## 8. Prochaines améliorations (v1.1+)

1. **Protection en temps réel** — `FileSystemWatcher` sur les dossiers critiques
2. **Mode démon** — Remplacer `clamscan.exe` par `clamd` (pas de rechargement des signatures à chaque scan)
3. **Tâche planifiée Windows** — Scan quotidien via le Planificateur Windows
4. **Notifications toast** — Alertes Windows natives à la détection d'une menace
5. **Score de risque** — Classification informationnel / mineur / critique
6. **Rapport PDF** — Export d'un rapport de scan complet
