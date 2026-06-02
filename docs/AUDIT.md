# Audit optiSCAN — synthèse unique (v7.0)

**Version** : 7.0.0 · **Release** : v7.0 · **Date** : juin 2026  
**Document de référence** : remplace les anciens audits Word / UI fragmentés.

---

## Verdict

**Produit publiable** après validation manuelle installateur + publish ClamAV/YARA sur machine propre.

| Domaine | Note | Commentaire |
|---------|:----:|-------------|
| Architecture | 8/10 | Services extraits ; `SignatureUpdateUiRunner`, `ScanLastScanDisplay` |
| Sécurité locale | 8/10 | Quarantaine AES-GCM, exclusions, UAC ; voir [THREAT-MODEL.md](THREAT-MODEL.md) |
| UI / Donaby | 8/10 | Accueil épuré, typo tokenisée (`FontSize.Display`), grilles animées |
| Réactivité | 7/10 | schtasks async ; `MainWindow` encore volumineux |
| i18n | 8/10 | ~530 clés FR/EN ; exports, MAJ signatures, ViewModel, ScanSession localisés |
| Tests & CI | 7/10 | **83** tests Release ; artefact publish + build Release sur CI |
| Release Inno | 8/10 | FR/EN, `AutoUpdateSignatures`, désinstall bilingue |

---

## Livraisons v7.0 (polish final)

- **Accueil** : hero Display 26 pt ; dernière analyse détaillée ; carte **État de protection** (ClamAV/YARA + signatures) en bas à droite
- **Typo / écriture** : Title Case sections ; stats lifetime courtes ; voix éditoriale dans [LOCALIZATION.md](LOCALIZATION.md)
- **Onboarding** : 3 étapes avec MAJ signatures optionnelle
- **Options** : libellés RTP / planification honnêtes (périmètre + UAC)
- **UI** : hover animé `DataGrid` ; MAJ signatures via `SignatureUpdateUiRunner`
- **Docs** : [THREAT-MODEL.md](THREAT-MODEL.md), README / index à jour

---

## Dettes ouvertes (post-v7.0 mineures)

| P | Sujet |
|---|--------|
| P2 | MVVM partiel ; `MainWindow.xaml.cs` ~880 lignes |
| P2 | Tests intégration `schtasks` réels |
| P3 | Canal OTA applicatif (informatif seulement) |

---

## Qualité automatisée

```powershell
dotnet test optiSCAN.Tests\optiSCAN.Tests.csproj -c Release   # 83 tests attendus
```

CI : [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)

Checklist manuelle : [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md).

---

## Documentation associée

| Fichier | Rôle |
|---------|------|
| [README.md](README.md) | Index `docs/` |
| [../README.md](../README.md) | Guide architecture |
| [BUILD.md](BUILD.md) | Publish, Inno |
| [LOCALIZATION.md](LOCALIZATION.md) | FR/EN, voix éditoriale |
| [THREAT-MODEL.md](THREAT-MODEL.md) | Périmètre sécurité local |
