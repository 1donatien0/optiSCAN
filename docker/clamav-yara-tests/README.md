# Tests d'intégration ClamAV / YARA (Linux)

Image Docker optionnelle pour valider la présence des binaires moteurs et l'exécution basique
hors Windows (CI Linux ou poste dev).

```bash
docker build -t optiscan-engine-tests -f docker/clamav-yara-tests/Dockerfile .
docker run --rm optiscan-engine-tests
```

Sur Windows, utiliser Docker Desktop ou WSL2.
