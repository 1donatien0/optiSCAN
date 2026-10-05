# Runtime .NET — mode de publication

L'installateur courant ne copie ni n'installe de runtime placé dans ce dossier.

- **Publication recommandée** : le profil `FolderProfile` est self-contained et inclut .NET dans le publish ; aucun runtime séparé n'est nécessaire sur le poste cible.
- **Publication framework-dependent** : le .NET 10 Desktop Runtime doit déjà être installé sur le poste cible. L'installeur ne le télécharge pas et n'installe pas de redist.

Pour intégrer un redist à une future version de l'installateur, il faudra reconnecter son inclusion et son exécution dans `installer/setup.iss`, puis valider ce parcours sur Windows.
