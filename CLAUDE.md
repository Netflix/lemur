# Lemur Certificate Orchestration

Datadog's fork of [Netflix/Lemur](https://github.com/netflix/lemur) — a TLS certificate lifecycle management platform (web UI + REST API). Upstream docs: https://lemur.readthedocs.io/en/latest/

**Deployments** (Kubernetes namespace: `cert-orchestration`):
- Sandbox: `https://lemur-sandbox.us1.staging.dog`
- Commercial: `https://lemur-commercial.us1.ddbuild.io`
- Government: `https://lemur-government.us1-build.fed.dog` (AppGate required; FIPS images)

## Critical Constraints

- **Do not bump `cryptography==43.0.1`** — exact version required for FIPS compatibility; bumping it breaks the Government deployment
- **Source syncs must stay sequential** — parallelizing them floods the Celery queue (this was an explicit bug fix, commit `0ad9ef89`)
- **Keep `requirements-base.in` and `requirements-datadog.in` separate** — upstream Netflix/lemur changes go in `requirements-base.in`; Datadog additions (Azure/GCP integrations, CVE overrides, version pins) go in `requirements-datadog.in`
- **The Celery beat schedule is in k8s-resources, not this repo** — to change a task schedule, edit `chart/config/lemur.conf.py` in [k8s-resources](https://github.com/DataDog/k8s-resources/tree/master/k8s/lemur), not `lemur/common/celery.py`
- **Government deployment has no Sectigo** — DigiCert only; don't add Sectigo config to the gov values file

## Configuration Lives in Separate Repos

### App config & Helm — [k8s-resources](https://github.com/DataDog/k8s-resources/tree/master/k8s/lemur)

```
chart/
  config/lemur.conf.py       # Application config (rendered from Vault via consul-template)
  values.yaml                # Image tag lives here — bump this to deploy a new release
  values/environments/
    us1.staging.dog.yaml
    us1.ddbuild.io.yaml
    us1-build.fed.dog.yaml
service.datadog.yaml         # Conductor schedule: staging=every commit, commercial/gov=Mon–Fri 12/14 UTC
```

Secrets are pulled from Vault at pod startup:
- Non-gov: `kv/data/k8s/cert-orchestration/lemur/`
- Gov: `kv/k8s/cert-orchestration/lemur/`

### Infrastructure — [cloud-inventory](https://github.com/DataDog/cloud-inventory)

PostgreSQL and Redis are managed via Terraform in cloud-inventory (the `terraform/` directory inside k8s-resources is obsolete):

| Environment | RDS | ElastiCache |
|-------------|-----|-------------|
| Staging | `datacenters/us1.staging.dog/lemur-db` | `datacenters/us1.staging.dog/lemur-cache` |
| Commercial | `datacenters/us1.ddbuild.io/lemur-db` | `datacenters/us1.ddbuild.io/lemur-cache` |
| Government | `datacenters/us1-build.fed/lemur-db` | `datacenters/us1-build.fed/lemur-cache` |

## Running Locally

### Docker (recommended)
```bash
cd local && docker-compose up -d   # starts lemur, postgres, redis, nginx
# UI at https://localhost:447
docker exec -u lemur -it <container_id> bash
```

### Without Docker
```bash
python3 -m venv venv && source venv/bin/activate
docker compose up -d postgres redis
make develop
export SQLALCHEMY_DATABASE_URI=postgresql://lemur:lemur@localhost:5432/lemur
cd lemur && lemur db upgrade
lemur -c <config_file> start
```

## Testing & Linting
```bash
make test          # lint + pytest (full suite)
make test-python   # pytest only
make lint-python   # flake8, max line length 100
```

PostgreSQL is required — provided by `docker-compose.yml`. Fixtures are in `lemur/tests/factories.py`.

## Database Migrations

Always run after pulling:
```bash
cd lemur && lemur db upgrade
```

After model changes, review the auto-generated file before committing:
```bash
cd lemur && lemur db migrate -m "description"
# review lemur/migrations/versions/<new file> carefully
```

## Dependencies

- `requirements.in` — upstream base (compiled to `requirements.txt`)
- `requirements-datadog.in` — Datadog overlay (see Critical Constraints above)
- `requirements-dd-source.in` — dd-source packages (COA plugin, `dd_internal_authentication`), installed separately by the Dockerfile
- Run `make up-reqs` inside a virtualenv to recompile all `.txt` files

## Telemetry (commercial instance)

- **Service tag**: `service:lemur`
- **APM**: https://app.datadoghq.com/apm/entity/service%3Alemur
- **Dashboard**: https://app.datadoghq.com/dashboard/dm6-549-pqh
- **Monitors** (prefixed `[Lemur]`): https://app.datadoghq.com/monitors/manage?q=%22%5BLemur%5D%22&p=1

## Release Process

Tag format: `1.0.0-dd.N`. Pushing a tag triggers GitLab CI to build and push prod images (regular + FIPS).

1. **Update `CHANGELOG.rst`** — add entry at the top (after the `Changelog` heading):
   ```rst
   1.0.0-dd.N - `YYYY-MM-DD`
   ~~~~~~~~~~~~~~~~~~~~~~~~~~

   Features:
   - Description (#PR)

   Bug fixes:
   - Description (#PR)

   Security fixes:
   - CVE description (#PR or Jira link)
   ```
   Omit empty sections. Commit to `master`.

2. **Push the tag**:
   ```bash
   git tag 1.0.0-dd.N && git push origin 1.0.0-dd.N
   ```

3. **Create the GitHub Release**:
   ```bash
   gh release create 1.0.0-dd.N --title "1.0.0-dd.N" --notes "$(cat <<'EOF'
   - Description (#PR)

   **Full Changelog**: https://github.com/DataDog/lemur/compare/1.0.0-dd.PREV...1.0.0-dd.N
   EOF
   )"
   ```

4. **Deploy**: bump image tag in `chart/values.yaml` in k8s-resources and open a PR.

Versioning: increment the trailing number only (`1.0.0-dd.(N+1)`).

## Runbooks & References
- Wiki: https://datadoghq.atlassian.net/wiki/spaces/NE/pages/2130608302/Lemur+Certificate+Orchestration
- Runbooks: https://datadoghq.atlassian.net/wiki/spaces/NE/pages/2591327746/Lemur+Certificate+Orchestration+Runbooks
- Upstream docs: https://lemur.readthedocs.io/en/latest/
- App config: https://github.com/DataDog/k8s-resources/tree/master/k8s/lemur
