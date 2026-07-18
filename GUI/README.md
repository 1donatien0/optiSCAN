# OptiWin GUI — intégré dans optiSCAN

> **Statut : obsolète (conservé pour référence).**
>
> Les fonctionnalités de cet utilitaire PowerShell (`OptiWin-GUI.ps1`) ont été
> portées en C# dans le panneau **Optimiser** d'optiSCAN (ex-panneau Nettoyer) :
>
> | Onglet OptiWin | Dans optiSCAN |
> |---|---|
> | Mises à jour (winget + Windows Update) | Optimiser → **Mises à jour** (`WingetUpdateService`) |
> | Nettoyage (temp, cache WU, corbeille, DNS, DISM) | Optimiser → **Nettoyage** (+ DISM dans **Tweaks**) |
> | Performance | Optimiser → **Tweaks** (`SystemTweaksService`) |
> | Confidentialité | Optimiser → **Tweaks** |
> | Interface | Optimiser → **Tweaks** |
>
> Les actions nécessitant les droits administrateur (télémétrie/DiagTrack,
> cache Windows Update, DISM) sont regroupées dans une seule invite UAC —
> l'application reste en `asInvoker`.
>
> Ce dossier peut être supprimé lors d'une prochaine release.
