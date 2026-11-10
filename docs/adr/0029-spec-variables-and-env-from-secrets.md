# 0029. Spec variables and variables from secrets

- Status: Accepted
- Date: 2026-11-10

## Context

A team that runs the same app in two environments keeps one spec and
changes a few values per environment: the image tag, the domains, the
replica limits. And an app that reads its settings from environment
variables usually has many secrets, imported from one file with `armada
secret import`, each of which had to be listed under `env` by hand. Without
support in Armada, deploy scripts filled placeholders with `sed` and built
the `env` list from `armada secret ls`, each in its own way.

## Decision

**Variables.** `armada deploy` takes `--var NAME=VALUE` and `--vars FILE`
(lines of `NAME=VALUE`; `--var` wins) and replaces `${NAME}` in the spec's
values before sending it. The substitution:

- happens only in the client and only when variables are given, so a spec
  deployed as before means what it meant before; the server sees an
  ordinary spec;
- never changes the document's structure: each `${NAME}` becomes a random
  placeholder before the YAML is parsed, and the value goes into the parsed
  scalar afterwards, so a value with newlines, colons, or brackets stays
  one value, and `${NAME}` needs no quotes inside flow collections;
- lets a plain value that is one variable take its type, so `max: ${MAX}`
  is a number, while quoted values stay strings;
- refuses a variable the spec uses but that is not set, and variables in
  keys; `$${` is a literal `${`. Variables a spec does not use are allowed,
  so one file per environment serves every app.

The client's environment is never read: only what the command names goes
into the spec. Values are stored with the revision like the rest of the
spec, so they are not for secrets.

**Variables from secrets.** `envFrom: secrets` in a spec gives the app every
one of its secrets as a variable, named like `armada secret import` names
them in reverse (`database-url` becomes `DATABASE_URL`). The server resolves
it in the deploy transaction, from the secrets the app has at that moment,
and stores the revision with the variables written out. So the revision
pins the secret versions as before, a rollback restores that revision's
variables, a secret rollout keeps them, and a deploy of the same spec with
the same secrets is the same revision. A secret added later reaches the app
with its next deploy, as a new value of an existing one does without a
rollout. Left out are variables the spec sets itself (they win), secrets
the spec uses for files or the registry, and names that are reserved or not
valid variable names. More than the limit of 512 variables is an error, not
a cut.

## Consequences

- One spec and one small file per environment replace placeholder
  scripts; the spec reference documents both features.
- Older servers refuse `envFrom` as an unknown field, so a spec that uses
  it needs the new version on the leader. Revisions written by a new
  leader carry their variables written out, which older servers read.
- `envFrom` puts every secret into the environment, which anyone with
  root on the node can read; `secretFiles` stays the better place for the
  most sensitive values, and secrets used as files are never also turned
  into variables.
