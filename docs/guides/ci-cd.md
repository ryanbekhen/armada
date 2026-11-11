# Deploy from CI

Your CI system builds an image for every commit; you want it to deploy that
image to Armada, run the database migration first, and fail the build when
the new revision does not come up. This guide sets that up with plain shell
steps that work in any CI system.

**You will use:** [services and roles](../operations.md#access-control),
[`armada app update`](../cli/armada-app.md#armada-app-update) with `--wait`
and `--diff`, [spec variables](../spec-reference.md#variables),
[`armada job run --wait`](../cli/armada-job.md#armada-job-run)
**Before you start:** a running cluster ([quickstart](../quickstart.md)),
`cluster-admin` access for the one-time setup, a project for the app (this
guide uses `shop`), and CI runners that can reach a control plane server's
private address on port 7443 (a runner inside the private network, or one
that joins it over a VPN).

## The setup

```
  git push --> CI: build + push ghcr.io/acme/api:sha-1a2b3c
                 |
                 |  armada (client config of service "ci", role deployer in shop)
                 v
           control plane :7443 (private)
                 |
                 |  1. job "migrate" runs with the new image, CI waits for it
                 |  2. app "api" rolls out the new image, CI waits for it
                 v
               nodes
```

The pipeline holds a **service**: an identity of its own with the
`deployer` role in one project, a 90-day certificate, and nothing else. It
cannot touch other projects, nodes, or cluster settings, and you can revoke
it without touching anyone's access.

## 1. Create the service (once, as cluster-admin)

```bash
armada project create shop                                  # if it does not exist yet
armada rbac service create ci --role deployer --project shop
armada rbac service credentials ci -o ci.json
```

`ci.json` is a client config: the servers' addresses, the cluster CA, and
the service's certificate and private key, created with mode `0600`. Store
its contents as a secret variable of your CI system (for example
`ARMADA_CLIENT_CONFIG`), then delete the local copy.

`deployer` may deploy, scale, roll back, set secrets, and run jobs in
`shop`. It may not run `armada app exec`, delete apps, or touch volumes;
give `admin` in the project if the pipeline needs those.

For pull requests, create a second service that can only read, so code
from a pull request never holds deploy rights:

```bash
armada rbac service create ci-preview --role viewer --project shop
armada rbac service credentials ci-preview -o ci-preview.json
```

## 2. Keep the specs in the repository

```yaml
# deploy/api.yaml
name: api
image: ghcr.io/acme/api:${TAG}
registry:
  server: ghcr.io
  username: acme-bot
  passwordSecretRef: ghcr-token
env:
  - name: DATABASE_URL
    secretRef: database-url
ingress:
  type: external
  port: 3000
  domains: [api.example.com]
probes:
  readiness:
    path: /healthz
scale:
  min: 2
resources:
  cpu: 250m
  memory: 512Mi
```

```yaml
# deploy/migrate.yaml
kind: job
name: migrate
image: ghcr.io/acme/api:${TAG}
registry:
  server: ghcr.io
  username: acme-bot
  passwordSecretRef: ghcr-token
command: ["./migrate", "up"]
env:
  - name: DATABASE_URL
    secretRef: database-url
timeout: 10m
resources:
  memory: 256Mi
```

`${TAG}` is filled in by `--var TAG=...` at deploy time. Secrets belong to
each app and job, so set them for both, once:

```bash
armada project use shop
for app in api migrate; do
  printf '%s' "$GHCR_TOKEN"   | armada secret set "$app" ghcr-token
  printf '%s' "$DATABASE_URL" | armada secret set "$app" database-url
done
```

See [private registry](private-registry.md) for the `registry` field.

## 3. The deploy step

Every CI system can run a shell script. This one installs the client,
writes the client config from the secret variable, migrates, and deploys:

```sh
#!/bin/sh
# deploy/deploy.sh: run by CI on the main branch after the image is pushed.
# Needs: ARMADA_CLIENT_CONFIG (secret), ARMADA_VERSION, TAG.
set -eu

# The client, pinned to the version your servers run (armada version).
curl -fsSL https://raw.githubusercontent.com/ryanbekhen/armada/main/install.sh |
  ARMADA_CLIENT_ONLY=1 ARMADA_VERSION="$ARMADA_VERSION" ARMADA_PREFIX="$HOME/.local" sh
export PATH="$HOME/.local/bin:$PATH"

# The client config must be 0600 and owned by the user running armada.
umask 077
printf '%s' "$ARMADA_CLIENT_CONFIG" > "$RUNNER_TEMP_DIR/armada.json"
export ARMADA_CONFIG="$RUNNER_TEMP_DIR/armada.json"
export ARMADA_PROJECT=shop

# 1. Migrate with the new image; stop here unless the run succeeds.
armada job update migrate --file deploy/migrate.yaml --var TAG="$TAG" --create-if-missing
armada job run migrate --wait --timeout 10m

# 2. Roll the app out; fail unless the new revision serves.
armada app update api --file deploy/api.yaml --var TAG="$TAG" --create-if-missing --wait --timeout 10m
```

Set `RUNNER_TEMP_DIR` to a directory your CI system cleans up after the job
(most provide one). Each step exits non-zero when it fails, so `set -e`
stops the script and the build goes red:

- `armada job run --wait` fails unless the run succeeded:
  `run 7 of migrate.shop failed with exit code 1: ...; see armada job
  logs migrate.shop --run 7`.
- `armada app update --wait` prints progress until the revision serves:

  ```
  Updated api.shop (revision api.shop--r8).
  api.shop--r8: 0/2 ready
  api.shop--r8: 1/2 ready
  api.shop--r8 is live (2/2 ready)
  ```

  When the rollout fails, it exits with `rollout of api.shop--r8 failed:
  api.shop--r8 made no progress within ...; api.shop--r7 stays active`. Nothing needs undoing: the old revision
  never stopped serving. When `--timeout` passes first, the command fails
  with `timed out after 10m0s waiting for api.shop--r8; the rollout
  continues on the server`.
- Deploying a commit whose spec and image did not change prints
  `api.shop is unchanged (revision api.shop--r7).` and succeeds.

Every change the pipeline makes is recorded in the audit log under the
name `service:ci`, and the leader's log names it too (`by=service:ci`).

### Only the image changes

When the spec lives elsewhere and CI only ships images, change the image
with a flag; everything else stays as it runs:

```sh
armada app update api --image "ghcr.io/acme/api:$TAG" --wait
```

An update from flags is refused when another change landed since the
command read the spec, so two pipelines cannot overwrite each other's
changes without noticing. Run the step again.

## 4. Show the change in pull requests

With the read-only `ci-preview` config, a pull request can show what its
spec change would do, without deploying:

```sh
armada app update api --file deploy/api.yaml --var TAG="$TAG" --diff
armada job update migrate --file deploy/migrate.yaml --var TAG="$TAG" --diff
```

`--diff` prints a line diff of the spec the app runs against the file, or
`No changes.`, and changes nothing. Post the output as a comment if your CI
system can.

## 5. Renew the certificate

A service certificate lasts 90 days. See when it expires:

```bash
armada rbac service list
```

```
NAME        ROLES                CERTIFICATES  EXPIRES
ci          deployer in shop     1             2027-02-09
ci-preview  viewer in shop       1             2027-02-09
```

Renew before then, from a trusted machine with the current file, and put
the new file into the CI secret right away:

```bash
armada rbac service renew --config ci.json   # rewrites ci.json with a new key and certificate
```

Renewing revokes every other certificate of the service, including the one
the CI secret still holds, so jobs fail until you update the secret. A
cluster-admin can also issue a fresh file at any time with `armada rbac
service credentials ci -o ci.json`; older files keep working until they
expire or the service renews.

If the file leaks, revoke everything at once and start again:

```bash
armada rbac service delete ci --yes
armada rbac service create ci --role deployer --project shop
armada rbac service credentials ci -o ci.json
```

## Check that it works

```bash
armada app show api            # the new revision serves; Image is the new tag
armada app revision list api   # one revision per deployed commit, with its digest
armada job run list migrate    # the migration runs, trigger manual
armada app events api          # Started and Completed rollouts
```

## Variations

**Several environments.** Use one project per environment (`shop-staging`,
`shop`) and one service per project, so the staging pipeline cannot touch
production. Keep per-environment values in `--vars` files (see
[spec files and environments](spec-files-and-environments.md)):

```sh
armada app update api --file deploy/api.yaml --vars deploy/production.env --var TAG="$TAG" --wait
```

**A canary first.** Deploy with `revisions.mode: multiple` and a small
weight for `latest`, check, then shift traffic with `armada app traffic`
(see [canary releases](canary-releases.md)).

**Migrations in the replica.** An init container runs the migration in
every replica before the app starts, instead of a separate job (see
[migrations and sidecars](migrations-and-sidecars.md)). The job is easier
to follow from CI: one run, one log, one exit code.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `service:ci may not deploy to project default`, or `service:ci may not see api` | The command works in another project than the one the service holds its role in | Set `ARMADA_PROJECT` (or `--project`) to that project; `armada rbac service show ci` shows its roles |
| `service:ci has no role that allows ...` | The method needs more than the service's role (`deployer` cannot exec or delete) | Give the role it needs with `armada rbac assignment create --service ci` |
| `... may not require node label tier=shop` | The spec's `placement.require` names a label the service may not use | `armada rbac service update ci --allow-label tier=shop` |
| `... has mode 0644, want 0600` | The config file was written without `umask 077` | Write it with `umask 077`, or `chmod 600` it |
| The command hangs, then fails to connect | The runner cannot reach the server's private address on port 7443 | Run the job on a runner in the private network or on its VPN |
| `app api.shop references secrets that are not set` | A secret was set for another app, project, or not at all | `armada secret set api NAME --project shop` |
| The certificate is refused after a renewal | The CI secret still holds the revoked file | Put the renewed file into the CI secret |

More in [troubleshooting](troubleshooting.md).

## Next steps

- [Private registry](private-registry.md): credentials for the image pull.
- [Teams and access](teams-and-access.md): users and roles for people.
- [Canary releases](canary-releases.md): ship to a share of traffic first.
- [`armada rbac service`](../cli/armada-rbac.md#armada-rbac-service) reference.
