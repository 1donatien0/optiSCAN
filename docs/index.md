# Documentation optiSCAN (DocFX)

Génération de la documentation API :

```powershell
dotnet tool install -g docfx
docfx metadata optiSCAN.sln --output api
docfx build docfx.json
```

Le site statique est produit dans `_site/`.
