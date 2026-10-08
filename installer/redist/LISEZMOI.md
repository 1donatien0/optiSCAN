# Runtime .NET — mode de publication

L'installateur courant ne copie ni n'installe de runtime placé dans ce dossier.

- **Scripts de release** : `FolderProfile`, `prepare-release-v3.ps1` et `publish-release.ps1` publient en self-contained et incluent .NET ; aucun runtime séparé n'est nécessaire sur le poste cible.
- **Publish manuel framework-dependent** : le .NET 10 Desktop Runtime doit déjà être installé sur le poste cible. L'installeur ne le télécharge pas et n'installe pas de redist.

Pour intégrer un redist à une future version de l'installateur, il faudra reconnecter son inclusion et son exécution dans `installer/setup.iss`, puis valider ce parcours sur Windows.
