# Pull images from a private registry

Your app's image lives in a private registry, and nodes need credentials to
pull it. This guide stores the registry password as a secret, points the
app at it, and shows what Armada does with those credentials.

**You will use:** [`registry`](../spec-reference.md#registry),
[secrets](../cli/armada-secret.md#armada-secret-set),
[init containers and sidecars](../spec-reference.md#initcontainers-sidecars),
[revisions](../cli/armada-app.md#armada-app-revision-list)
**Before you start:** a running cluster ([quickstart](../quickstart.md)), a
project you may deploy to (this guide uses `shop`), and a read-only token
for your registry, such as a GitHub personal access token with
`read:packages` for `ghcr.io`.

## The setup

```
  armada secret set api ghcr-token        spec: registry.passwordSecretRef: ghcr-token
              |                                         |
              v                                         v
     control plane (encrypted) ---- assignment ----> agent on each node
                                                        |
                                                        | pulls with the token, only from ghcr.io
                                                        v
                                                     ghcr.io/acme/api@sha256:...
```

The password never appears in the spec, in `armada app show`, or in logs.
The control plane decrypts it only while it builds the assignment for a
node that runs the app.

## 1. Store the registry password as a secret

A secret belongs to one app, so name the app you are about to create.
Read the token from a file or stdin, never from an argument:

```bash
armada project use shop
printf '%s' "$GHCR_TOKEN" | armada secret set api ghcr-token
armada secret list api
```

```
NAME        VERSION  UPDATED              BY          USED BY
ghcr-token  1        2026-11-11 10:02:11  user:alice  -
```

Set the secret before you create the app: a deploy that names a secret
which is not set is refused, with the `armada secret set` command to run.

## 2. Point the app at the registry

From flags, `--registry-user` and `--registry-secret` fill in `registry`;
the server is always the registry of `--image`:

```bash
armada app create api --image ghcr.io/acme/api:1.4.2 --port 3000 --ingress external \
  --registry-user acme-bot --registry-secret ghcr-token --replicas 2 --wait
```

Or in a spec file, which you keep in git:

```yaml
# api.yaml
name: api
image: ghcr.io/acme/api:1.4.2
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
initContainers:
  - name: migrate
    image: ghcr.io/acme/api:1.4.2
    command: ["./migrate", "up"]
    env:
      - name: DATABASE_URL
        secretRef: database-url
    resources:
      memory: 256Mi
sidecars:
  - name: metrics-agent
    image: ghcr.io/acme/metrics-agent:2.0.1
    resources:
      cpu: 50m
      memory: 64Mi
```

```bash
printf '%s' "$DATABASE_URL" | armada secret set api database-url
armada app create --file api.yaml --wait
```

- `server` must be the registry the image names: `ghcr.io` for
  `ghcr.io/acme/api`, `docker.io` for an image without a registry host such
  as `acme/api`. Anything else is refused with `registry.server: must match
  the registry of image (...)`.
- `passwordSecretRef` is always a secret. There is no field for an inline
  password.
- The registry secret is not turned into a variable by `envFrom: secrets`.

## 3. Know where the credentials go

- **Only to that registry.** A node answers the registry's login request
  with these credentials only when the host matches `registry.server`
  (`docker.io`, `index.docker.io`, and `registry-1.docker.io` count as one).
  An image from any other registry is pulled anonymously, so one app's
  token is never sent to a registry it was not meant for.
- **Init containers and sidecars** use the same credentials when their
  image is on the same registry, like `migrate` and `metrics-agent` above.
  An init container or sidecar from another registry must be public. An
  app has one `registry`, so keep the images a replica needs on one
  private registry.
- **Jobs** take the same field, and `armada job create` takes the same
  `--registry-user` and `--registry-secret` flags.

## 4. Know which image runs

The first node that pulls a revision's image resolves its tag to a digest,
and every replica of that revision runs exactly that digest, even if
someone pushes the tag again later:

```bash
armada app revision list api
```

```
REVISION      STATUS  CREATED              IMAGE                   PLATFORMS    DIGEST
api.shop--r2  active  2026-11-11 10:04:37  ghcr.io/acme/api:1.4.2  linux/amd64  sha256:4f1c...
api.shop--r1  -       2026-11-09 16:20:05  ghcr.io/acme/api:1.4.1  linux/amd64  sha256:9b07...
```

A rollback runs the digest that ran before. The app's own image is the only
one pinned this way: init container and sidecar images are pulled as
written, so write `ghcr.io/acme/metrics-agent:2.0.1@sha256:...` where every
replica must run the same build.

## Check that it works

```bash
armada app show api            # Ready: 2/2, no "pull" message on the replicas
armada app events api          # Scheduled, Started, Ready for each replica
```

## Variations

**Docker Hub.** Leave the registry host out of the image and use
`docker.io` as the server:

```yaml
# worker.yaml
name: worker
image: acme/worker:3.2.0
registry:
  server: docker.io
  username: acmebot
  passwordSecretRef: dockerhub-token
command: ["./worker"]
env:
  - name: REDIS_URL
    secretRef: redis-url
resources:
  memory: 256Mi
```

**A registry on its own port**, such as `registry.example.com:5000/acme/api:1.4.2`:
the server is `registry.example.com:5000`.

**Moving the app to another registry.** `armada app update api --image
registry.example.com/acme/api:1.4.3` changes `registry.server` with it.
Set the new registry's password first, then name it:

```bash
printf '%s' "$NEW_TOKEN" | armada secret set api registry-token --no-rollout
armada app update api --image registry.example.com/acme/api:1.4.3 --registry-secret registry-token --wait
```

**A public image again.** `armada app update api --registry-user ""
--registry-secret ""` removes `registry`.

## Rotating the token

```bash
printf '%s' "$NEW_GHCR_TOKEN" | armada secret set api ghcr-token --wait
```

The serving revision uses the secret, so this rolls out a new revision that
pins the new version. Two things to keep in mind:

- Revisions pin secret versions. A rollback to an older revision uses the
  token that revision pinned, and nodes pull its image again if they
  removed it (every node removes images that no container uses and that
  were pulled more than an hour ago). Revoke
  an old token only once you no longer need to roll back past the rotation.
- `--no-rollout` stores the new version without a rollout; the next deploy
  picks it up.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Replicas `failed`, message `pull ghcr.io/acme/api:1.4.2: ...` with `401` or `403`, and a `Failed` replica event | Wrong user, expired token, or a token without read access to the package | Set the secret again with a working token; `armada secret set` rolls the app out |
| Same message with `not found` | The tag does not exist, or the token cannot see the repository | Check the tag in the registry; check the token's scope |
| A sidecar or init container fails to pull while the app's image works | Its image is on another registry and is private | Move it to the app's registry, or make it public |
| `Rollout: api.shop--r3 failed, api.shop--r2 kept serving: no progress within ...` after a pull error | The new revision never started; the old one keeps serving | Fix the credentials or the tag, then deploy again |
| `app api.shop references secrets that are not set: ghcr-token` | The secret was not set, or was set for another app or project | `armada secret set api ghcr-token --project shop` |

See [troubleshooting](troubleshooting.md#image-pull-fails) for images built
for the wrong platform.

## Next steps

- [Deploy from CI](ci-cd.md): build, push, and deploy the new tag.
- [Spec files and environments](spec-files-and-environments.md): one spec, several clusters.
- [Migrations and sidecars](migrations-and-sidecars.md): more on init containers.
- [`registry`](../spec-reference.md#registry) in the spec reference.
