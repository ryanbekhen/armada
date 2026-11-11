# Run staging and production from one spec file

Keep one spec file per app in your repository and deploy it to staging and
production with different values: domains, replica counts, resources, and
the image tag. Each environment is a project with its own secrets. Use this
once an app has more than one place to run.

**You will use:** [spec variables](../spec-reference.md#variables)
(`--vars`, `--var`), [projects](../operations.md#projects)
(`--project`, `armada project use`), [secrets](../cli/armada-secret.md)
(`armada secret set`, `armada secret import`),
[`envFrom: secrets`](../spec-reference.md#envfrom),
[`secretFiles`](../spec-reference.md#secretfiles),
[`armada app update`](../cli/armada-app.md#armada-app-update) with
`--diff` and `--create-if-missing`

**Before you start:**

- A running cluster with a root domain (see the [quickstart](../quickstart.md)).
  Here: `apps.example.com`.
- `cluster-admin`, or the `project-creator` role, to create projects. After
  that, `deployer` in a project is enough to set secrets and deploy;
  `armada app exec` needs `admin` (see
  [teams-and-access.md](teams-and-access.md)).
- For `secretFiles`: each node's secrets directory on tmpfs
  (`armadad doctor` checks it).
- [deploy-a-web-app.md](deploy-a-web-app.md) if you have not deployed an
  app yet.

## The setup

```
 repository                       cluster
 ┌──────────────────┐             ┌─ project staging ─────────────────────┐
 │ deploy/api.yaml  │──staging.env─▶ api.staging   secrets: staging values │
 │ deploy/          │             │  https://api.staging.example.com       │
 │   staging.env    │             ├─ project production ──────────────────┤
 │   production.env │──prod.env───▶ api.production secrets: prod values   │
 └──────────────────┘             │  https://api.example.com               │
                                  └────────────────────────────────────────┘
```

- The **spec** holds what is the same everywhere, with `${NAME}` where
  environments differ.
- A **vars file** per environment holds the values that differ and are not
  secret. It lives in git next to the spec.
- **Secrets** live in the cluster, per app and project, never in git or in
  variables.
- A **project** per environment keeps names apart: `api` in `staging` and
  `api` in `production` are two apps, `api.staging` and `api.production`.

## 1. Write the spec with variables

`deploy/api.yaml`:

```yaml
name: api
image: ghcr.io/acme/api:${TAG}
env:
  - name: APP_ENV
    value: ${ENV}
  - name: LOG_LEVEL
    value: ${LOG_LEVEL}
envFrom: secrets
secretFiles:
  - secretRef: jwt-signing-key
    path: /run/secrets/jwt.pem
ingress:
  type: external
  port: 3000
  domains: [${API_DOMAIN}]
probes:
  readiness:
    path: /healthz
scale:
  min: ${API_MIN}
  max: ${API_MAX}
  rules:
    - type: http
      concurrent: 40
resources:
  cpu: "${API_CPU}"
  memory: 512Mi
```

`deploy/staging.env`:

```
# staging.env
ENV=staging
LOG_LEVEL=debug
API_DOMAIN=api.staging.example.com
API_MIN=1
API_MAX=2
API_CPU=250m
```

`deploy/production.env`:

```
# production.env
ENV=production
LOG_LEVEL=info
API_DOMAIN=api.example.com
API_MIN=2
API_MAX=8
API_CPU=1
```

How variables behave:

- `--vars FILE` reads `NAME=VALUE` lines (blank lines and `#` comments are
  skipped); `--var NAME=VALUE` sets one and wins over the file. The image
  tag changes with every release, so it comes from `--var TAG=...` rather
  than a file.
- A variable the spec uses but neither sets is an error, never an empty
  value. A file may hold variables a spec does not use, so one file per
  environment can serve every app.
- A value that is a variable alone takes its type: `min: ${API_MIN}` is a
  number. `cpu: "${API_CPU}"` stays a string because of the quotes.
- A value never changes the spec's structure: `[${API_DOMAIN}]` is a list
  of one domain whatever the value holds.
- Values end up in the revision like the rest of the spec, and anyone who
  can read the app sees them. Secrets go in secrets.

## 2. Create a project per environment

```bash
armada project create staging
armada project create production
armada project list
```

```
PROJECT     APPS  NETWORK   CREATED  BY
default     0     open      -        -
production  0     isolated  4s ago   user:you
staging     0     isolated  9s ago   user:you
```

A command works in one project:

- `--project NAME` (or the `ARMADA_PROJECT` variable) for one command;
- `armada project use NAME` saves it in your client config, so every later
  command works there until you `use` another (`armada project use default`
  goes back);
- `NAME.PROJECT` names an app of another project:
  `armada app show api.production`.

This guide passes `--project` everywhere, which is what scripts and CI
should do: a saved project is easy to forget.

On a cluster with the cluster network, the containers of `staging` and
`production` cannot reach each other: `api` in staging resolves only
staging's internal names. Projects keep apps you operate apart; they are
not a boundary against hostile code (see
[operations](../operations.md#sharing-a-cluster)).

## 3. Set the secrets

Secrets belong to an app in a project, and you can set them before the app
exists. Put the plain values in a file you do not commit:

```
# staging.secrets.env (never in git)
DATABASE_URL=postgres://api:s3cret@db.staging.internal:5432/api
REDIS_URL=redis://:s3cret@redis.staging.internal:6379/0
STRIPE_API_KEY=sk_test_51...
```

```bash
armada secret import api staging.secrets.env --project staging
armada secret set api jwt-signing-key --from-file jwt-staging.pem --project staging
armada secret list api --project staging
```

```
NAME             VERSION  UPDATED              BY        USED BY
database-url     1        2026-11-10 09:12:04  user:you  -
jwt-signing-key  1        2026-11-10 09:12:09  user:you  -
redis-url        1        2026-11-10 09:12:04  user:you  -
stripe-api-key   1        2026-11-10 09:12:04  user:you  -
```

- `secret import` turns `DATABASE_URL` into the secret `database-url`. A
  value is everything after the first `=`, kept exactly, quotes included.
- `secret set` reads the value from stdin, a hidden prompt, or
  `--from-file` (the file's bytes, exactly). Values are never accepted as
  arguments, because they would end up in your shell history.
- Values are never shown again. `secret list` shows names and versions.

Do the same for production with its own values and `--project production`.

### How the app gets them

- **`envFrom: secrets`** gives the app every secret as a variable: its
  name in capitals with `_` for `-`, so `database-url` becomes
  `DATABASE_URL`. A variable that `env` sets itself wins, and secrets used
  in `secretFiles` or `registry` are left out, so `jwt-signing-key` is not
  also an environment variable.
- **`secretFiles`** mounts a secret read-only at a path, on tmpfs. Prefer
  files for keys and certificates: environment variables are visible to
  anyone with root on the node.
- To name variables yourself instead, list them in `env`:

  ```yaml
  env:
    - name: DB_URL
      secretRef: database-url
  ```

A deploy pins the secret versions it uses, so a rollback brings back the
values of that revision too.

## 4. Deploy to staging

Look first. `--diff` prints what would change and changes nothing; for an
app that does not exist yet, every line is new:

```bash
armada app update api --project staging \
  --file deploy/api.yaml --vars deploy/staging.env --var TAG=1.4.2 --diff
```

Then deploy. `--create-if-missing` creates the app the first time and
updates it every time after, so the same command works for both:

```bash
armada app update api --project staging \
  --file deploy/api.yaml --vars deploy/staging.env --var TAG=1.4.2 \
  --create-if-missing --wait
```

```
Created api.staging (revision api.staging--r1).
api.staging--r1: 0/1 ready
api.staging--r1 is live (1/1 ready)
```

Verify the domain as in [deploy-a-web-app.md](deploy-a-web-app.md#3-add-your-own-domain):

```bash
armada domain list --app api --project staging      # prints the TXT record to publish
armada domain verify api.staging.example.com
```

A domain belongs to one project, so staging and production need different
domains. Until it is verified, the app is reachable at
`https://api.staging.apps.example.com`.

## 5. Promote the same image to production

```bash
armada app update api --project production \
  --file deploy/api.yaml --vars deploy/production.env --var TAG=1.4.2 --diff

armada app update api --project production \
  --file deploy/api.yaml --vars deploy/production.env --var TAG=1.4.2 \
  --create-if-missing --wait
```

The spec is the same file; only the variables and the secrets differ.

## 6. Release the next version

```bash
armada app update api --project staging \
  --file deploy/api.yaml --vars deploy/staging.env --var TAG=1.5.0 --diff
```

```
  kind: app
  name: api
- image: ghcr.io/acme/api:1.4.2
+ image: ghcr.io/acme/api:1.5.0
  env:
    - name: APP_ENV
      value: staging
```

The diff compares the file, as the cluster would store it, with the spec
the app runs. When the only change is the tag, as here, nobody changed the
app behind your back. Deploy without `--diff`, test, then run the same for
production.

A secret you changed with `secret import` reaches the app with this
deploy. `secret set` on a secret the app already uses rolls the app out by
itself (`--no-rollout` stores it for the next deploy). A secret that is new
since the last deploy becomes a variable through `envFrom` only with the
next deploy.

## Conflicts between changes

Two ways to change an app behave differently:

- **Flag updates** (`armada app update api --env FEATURE_X=on`) read the
  spec the app runs, change the fields the flags name, and send it back
  with the revision they read. If another change landed in between, the
  update is refused rather than undoing it:

  ```
  Error: api.production changed since api.production--r7 (now api.production--r8); run the command again
  ```

  Run the command again: it starts from the new spec.

- **File updates** (`--file`) replace the whole spec. They do not check
  what changed in between: anything changed with flags since, and not in
  your file, is undone. Run `--diff` first, and make the file the only way
  your team changes an app. A hotfix made with flags belongs in the file
  before the next deploy.

## Check that it works

```bash
armada app list -A
```

```
PROJECT     NAME  READY  STATE  REVISION            IMAGE                   URL
production  api   2/2    ready  api.production--r1  ghcr.io/acme/api:1.4.2  https://api.production.apps.example.com/
staging     api   1/1    ready  api.staging--r2     ghcr.io/acme/api:1.5.0  https://api.staging.apps.example.com/
```

The list shows the first URL; `armada app show api --project production`
lists the custom domain too.

```bash
armada app exec api --project staging -- printenv APP_ENV DATABASE_URL
armada app exec api --project staging -- ls -l /run/secrets/
```

The first prints `staging` and the staging database URL, read inside the
container. Use it to check wiring, not to read secrets: exec is audited.

## Variations

**A file per environment instead of variables.** When environments differ
in structure (a sidecar only in production, a `placement` only for
production nodes), variables cannot help, since a value never changes the
structure. Keep `api.staging.yaml` and `api.production.yaml`, and still use
`--var TAG` for the image.

**Preview environments.** Create a project per branch with
`armada project create pr-42`, deploy with the staging vars and
`--var API_DOMAIN=...`, and delete it after: delete its apps
(`armada app delete api --project pr-42 --yes`), then
`armada project delete pr-42`. A project can only be deleted once it is
empty.

**Literal `${`.** With `--var` or `--vars`, write `$${` for a literal `${`.
Without them, the spec is taken as written.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Error: the spec uses variables that are not set: TAG` | A variable has no value | Add it to the vars file or pass `--var TAG=...` |
| `app api.staging references secrets that are not set: jwt-signing-key` | The spec names a secret the app does not have in this project | `armada secret set api jwt-signing-key --project staging` |
| `api.production does not exist: create it with armada app create, or pass --create-if-missing` | First deploy to this project | Add `--create-if-missing` |
| `domain api.example.com is used by project staging` | A domain belongs to one project | Use a different domain per environment |
| The app does not see a new secret | `secret import` does not roll out, and `envFrom` takes the list at deploy | Deploy again (the same file and tag is fine) |
| `armada app list` shows nothing | You are in another project | `armada project list`, `--project NAME`, or `armada app list -A` |
| Replicas fail to start with a message about the secrets directory | The node's secrets directory is not on tmpfs, so `secretFiles` cannot be written | Run `armadad doctor` on that node and fix the `FAIL` |

## Next steps

- [ci-cd.md](ci-cd.md): run these commands from a pipeline with a service
  certificate.
- [canary-releases.md](canary-releases.md): release to production in steps.
- [teams-and-access.md](teams-and-access.md): `deployer` in staging, `viewer`
  in production.
- [app-with-a-database.md](app-with-a-database.md).
- [Spec reference: variables](../spec-reference.md#variables).
