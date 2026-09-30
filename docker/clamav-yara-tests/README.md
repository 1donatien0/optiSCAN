# Smoke tests ClamAV + YARA dans Docker (CI job engine-docker-smoke).

```bash
docker build -t optiscan-engine-tests -f docker/clamav-yara-tests/Dockerfile .
docker run --rm optiscan-engine-tests
```
