# Plan de release — optiSCAN v3.2

**Ouverte le 13 novembre 2026. Travail de code commencé le 14 novembre.** La 3.2 est la candidate à la signature. Le tag `v3.1.0` reste la version publique. `Directory.Build.props` porte `3.2.0` dans l'arbre de travail. On ne soumet à SignPath qu'une fois la piste ci-dessous vérifiée par les tests et les signes publics de la 3.1.0 réunis.

## Pourquoi la signature attend

La SignPath Foundation a refusé la candidature le 13 novembre 2026. Le motif, dans la lettre de Phillip, est l'absence de signaux publics : étoiles et forks GitHub, contributeurs, articles, discussions (Reddit, Stack Overflow, YouTube) ou soutien institutionnel, et une activité suivie. Ce n'est pas un jugement sur le code.

Recandidater le jour du refus, avec un simple changement de numéro, n'ajoute aucun de ces signaux. La prochaine demande partira quand la 3.1.0 aura été téléchargée et que le dépôt montrera une activité visible (issues, discussions, étoiles). La chaîne technique reste en place : `.signpath/`, `.github/workflows/release.yml`, [politique de signature](docs/CODE_SIGNING_POLICY.md), [procédure](docs/SIGNATURE_PROCEDURE.md). Elle n'est pas retirée du dépôt.

## Piste retenue — persistance des clés

Audit statique du 14 novembre 2026, priorité **P2**. La correction est dans l'arbre de travail, pas encore publiée. Les notes d'origine restent sur le bureau : `Audit/Synthese-audit-optiSCAN.md` et `Audit/Pistes-corrections-optiSCAN.md`.

`GetOrCreateDpapiHmacKeyMaterial` dans `optiSCAN.Engine/Services/SecureStore.cs` et `LoadOrCreateMasterKey` dans `optiSCAN.Engine/Services/QuarantineManager.cs` génèrent une clé, puis la retournent même si `ProtectedData.Protect` ou l'écriture du fichier échoue. L'échec est seulement journalisé. Une enveloppe de préférences ou un fichier de quarantaine peut alors être écrit avec une clé qui n'existe plus au redémarrage : `Load` refuse l'enveloppe, et la quarantaine de cette session ne se déchiffre plus.

La correction, adaptée au filtre `when (!ex.IsFatal())` du projet :

- ne pas retourner une clé neuve tant que son fichier DPAPI n'est pas écrit ;
- `TrySave` du magasin sécurisé retourne `false` et n'écrit pas l'enveloppe ;
- le gestionnaire de quarantaine ne démarre pas avec une clé seulement en mémoire ; la quarantaine est indisponible pour les nouvelles opérations ;
- conserver le repli actuel qui met de côté une clé ou un manifeste illisibles ;
- effacer la clé en mémoire si la persistance échoue.

Vérifications avant de soumettre la 3.2 : échec d'écriture simulé sur chemins temporaires, sans provoquer une vraie panne disque. Après échec puis redémarrage, les données déjà lisibles le restent. Les sauvegardes normales et la migration du magasin en clair passent encore.

## Ce que la 3.2 devra montrer

- Le tag `v3.1.0` et l'installeur `optiSCAN_Setup_v3.1.0.exe` publiés, avec leur empreinte SHA-256.
- La page SourceForge de la 3.1 qui dit clairement que ce fichier n'est pas signé.
- Des signes extérieurs accumulés depuis cette publication, cités dans la nouvelle demande.
- La piste « persistance des clés » corrigée et couverte par les tests décrits ci-dessus.
- Une 3.2 compilée par GitHub Actions, puis soumise à la signature seulement après une nouvelle acceptation.

## Visibilité

Fiche AlternativeTo déjà publique, non citée dans la première candidature :

https://alternativeto.net/software/optiscan/about/

Constat du 13 novembre 2026 sur cette URL, et seulement ce que la page affiche :

- Titre de l'onglet : « optiSCAN: Free and open-source antivirus and PC optimizer for Windows, built on ClamAV ». Titre de la fiche : optiSCAN.
- Description affichée : antivirus et outil de nettoyage gratuit, sous GPL, pour Windows 10 et 11 ; moteurs ClamAV et YARA ; analyses, quarantaine, mises à jour de signatures, protection temps réel optionnelle ; nettoyage, winget et réglages réversibles ; interface anglais et français ; exécution locale, à côté de Windows Defender.
- Compteurs : 0 like, 0 commentaire, 0 article, 27 alternatives. Licence affichée : gratuite et open source (GPL-3.0). Langages de l'interface : anglais et français. Écrit en C#. Plate-forme : Windows. Pastilles : « Since : New », « Updated : Oct 2026 ».
- La page ne nomme pas les 27 alternatives. Le bloc « Popular alternatives » cite Malwarebytes Anti-Malware, ClamAV et Avast Free Antivirus, avec un lien « View all ». L'activité cite en plus Spybot - Search & Destroy et Avira Antivirus, puis « and 23 more ».
- Ajoutée par donaby le 17 octobre 2026 ; dernière mise à jour de la page le même jour. Activités libellées « 28 days ago » : donaby a ajouté la fiche, Paul l'a mise à jour, donaby l'a ajoutée comme alternative aux logiciels ci-dessus.
- Aucune mention de revendication sur la page : pas de texte « claim », pas de badge « claimed ». Un bouton « Contribute to this app » est présent.
- Liens officiels au moment de la lecture : site `github.com/1donatien0/optiSCAN`, et un lien GitHub sous « AppStores & Other Links ». Le bloc GitHub de la fiche affiche 0 étoile, 0 fork, 0 issue ouverte, « Updated Oct 19, 2026 ». Aucun lien SourceForge n'était encore affiché.
- Le 13 novembre 2026 au soir, le lien SourceForge a été soumis sur la fiche. La modification est en attente de validation par AlternativeTo ; elle n'est pas encore visible publiquement.

Cette fiche ne suffit pas, à elle seule, à recandidater le jour du refus. Elle devra figurer dans la prochaine lettre, à côté des téléchargements SourceForge (environ 37 par semaine, dont environ 33 pour la 3.0.0 : https://sourceforge.net/projects/optiscan/).

Paragraphe en anglais, prêt à coller dans une future lettre à SignPath. Il n'est pas à envoyer. Il ne dit pas que la Fondation a accepté le projet, ni que les binaires sont signés.

optiSCAN has a public AlternativeTo listing that was not cited in the first application: https://alternativeto.net/software/optiscan/about/ . Checked on 13 November 2026, the page was added by donaby on 17 October 2026 and last updated the same day. It shows 0 likes, 0 comments, 0 articles and 27 alternatives, and it does not present the listing as claimed. Its official links point only to the GitHub repository https://github.com/1donatien0/optiSCAN ; the page's own GitHub block shows 0 stars, 0 forks and 0 open issues, updated 19 October 2026. On 13 November 2026 the page did not yet show a SourceForge link; a SourceForge link was submitted the same evening and is pending AlternativeTo review. The SourceForge project (https://sourceforge.net/projects/optiscan/) distributes the installer unsigned, at about 37 downloads a week, of which about 33 are for version 3.0.0. These are public references for a later letter only. They are not a new application, they do not mean that the SignPath Foundation has accepted the project, and they do not mean that any optiSCAN binary is code-signed.

## Hors de cette ouverture

Le minifiltre, la compilation de YARA en CI et le reste de la [feuille de route](ROADMAP.md) ne sont pas décidés par le seul fait d'ouvrir la 3.2. Chaque chantier reste un engagement séparé.
