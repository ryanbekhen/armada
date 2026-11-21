# Secrets shared by several apps

An API, its worker, and its migration job usually need the same database
URL, mail password, and API keys. Put them in one secret of the space and
let each app use it, instead of a copy per app. Change a value once, and
every app that uses it rolls out with the new one.

**You will use:** [`armada secret`](../cli/armada-secret.md),
[secret references](../spec-reference.md#secret-references), and
[`envFrom`](../spec-reference.md#envfrom).

## How secrets work

- A **secret** is a named set of keys in a space, for example `db` with
  `DATABASE_URL` and `PASSWORD`. Every app and job of the space can use it;
  apps of other spaces cannot.
- A spec names a key as `SECRET/KEY` (`db/DATABASE_URL`), or lists whole
  secrets under `envFrom`.
- The secret named after an app is that app's own: `secretRef: jwt-key`,
  with no secret named, is the key `jwt-key` of the secret `api` for the
  app `api`. Specs written that way keep working as they are.
- Values are write-only: they are read from a file or stdin, never from a
  command line, and never shown again.

## 1. Create the secret

Write the values to a file outside git:

```bash
# shared.env (never in git)
DATABASE_URL=postgres://app:s3cret@db.internal:5432/app
REDIS_URL=redis://:s3cret@redis.internal:6379/0
SMTP_PASSWORD=mail-s3cret
```

```bash
armada secret create shared --from-env-file shared.env
rm shared.env
armada secret show shared
```

```
KEY            VERSION  UPDATED              BY        USED BY
DATABASE_URL   1        2026-11-21 10:00:00  user:you  -
REDIS_URL      1        2026-11-21 10:00:00  user:you  -
SMTP_PASSWORD  1        2026-11-21 10:00:00  user:you  -
```

Keys keep the names in the file. Add or change one later with
`armada secret set shared KEY < value.txt`.

## 2. Use it in each app

Every key as a variable:

```yaml
name: api
image: ghcr.io/acme/api:1.4.2
envFrom:
  - secret: shared
ingress:
  type: external
  port: 8080
```

Or only the keys an app needs, under names of your own:

```yaml
name: worker
image: ghcr.io/acme/worker:1.4.2
env:
  - name: DB_URL
    secretRef: shared/DATABASE_URL
  - name: QUEUE_URL
    secretRef: shared/REDIS_URL
ingress:
  type: none
```

From the command line, the same:

```bash
armada app deploy api --env-from shared
armada app deploy worker --secret-env DB_URL=shared/DATABASE_URL
```

`armada secret list` shows the space's secrets and which apps use them:

```
NAME    KEYS  UPDATED              BY        USED BY
shared  3     2026-11-21 10:00:00  user:you  api,worker
```

## 3. Change a value

```bash
armada secret set shared DATABASE_URL < new-url.txt --wait
```

Every app whose current revision uses `DATABASE_URL` rolls out with the
new value, one rollout each; `--no-rollout` stores it for their next
deploy instead. A revision keeps the values it was deployed with, so
`armada app rollback` brings the old ones back too.

## 4. Move an app's own keys into a shared secret

An app that has its own keys (`armada secret show api`) keeps running as
it is. To share them, one app at a time:

1. Create the shared secret with the same values, as in step 1.
2. Change the app's spec to read it. To keep the app's own keys as well,
   list both: `envFrom: [{secret: shared}, {secret: api}]`, where a key of
   a secret listed first wins.
3. Deploy, and check the app with `armada app show api`.
4. Remove the copies the app no longer uses:
   `armada secret unset api database-url`. A key a serving revision still
   uses is refused, so nothing breaks by accident.

## Troubleshooting

| Error | Cause | Fix |
| --- | --- | --- |
| `envFrom names the secret shared, which has no keys` | The secret does not exist in this space | `armada secret list` (with `--space`), then create it |
| `app api references secrets that are not set: shared/DATABASE_URL` | The key is missing | `armada secret set shared DATABASE_URL` |
| `secrets of the space ... need every control plane server on this version first` | A server still runs an older release | Upgrade every server (`armada server list`), then deploy again |
| `key DATABASE_URL of secret shared is used by revision api--r4` | `secret delete` while an app uses it | Deploy the apps without it first; `secret show shared` lists them |
