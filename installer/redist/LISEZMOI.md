# Runtime .NET embarqué (optionnel)

Pour un installeur **autonome hors-ligne** (+~56 Mo), placer ici le runtime
téléchargé depuis https://dotnet.microsoft.com/download/dotnet/8.0 :

```
installer\redist\windowsdesktop-runtime-win-x64.exe
```

(fichier officiel `windowsdesktop-runtime-8.0.x-win-x64.exe`, renommé sans numéro de version)

- **Présent** → embarqué dans le setup, installé localement si .NET 8 manque.
- **Absent** → le setup télécharge le runtime (lien officiel `aka.ms/dotnet/8.0/...`) seulement s'il manque sur la machine.

Ne pas committer l'exe dans Git (`installer/redist/*.exe` est déjà dans `.gitignore`).

Détails chaîne de release : [docs/GUIDE_DISTRIBUTION.md](../../docs/GUIDE_DISTRIBUTION.md) §3.
