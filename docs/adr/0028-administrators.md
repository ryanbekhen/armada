# 0028. Administrators

- Status: Accepted
- Date: 2026-11-09

## Context

`armadad init` issues one administrator certificate. Everyone who
administers the cluster used that certificate, or a copy of it, so:

- the audit log named the same identity for every person's actions;
- taking one person's access away meant changing the certificate for
  everyone, and even then the old one kept working until it expired a year
  later, because administrator certificates could not be revoked.

## Decision

Each person gets an administrator certificate under their own name, and the
cluster keeps a record of administrators by name, under `admins/` in the
state (schema 8):

- `armada admin add NAME -o FILE` creates a key on the caller's machine and
  asks the leader (`AddAdmin`) to sign it as `admin:NAME`. The leader records
  the name with the certificate's start time (`Since`) and audits it, and the
  client writes a client config for that person. Certificates the name was
  given earlier are refused from then on. A name already on record and not
  removed is refused, and so is the caller's own name (that is `armada admin
  renew`).
- `armada admin rm NAME --yes` (`RemoveAdmin`) marks the name removed, which
  refuses every certificate of it at once on every server. The record stays,
  so a name that was never on record can be removed too. Nobody can remove
  themselves, so at least one administrator is always left. `admin add` gives
  a removed name a new certificate.
- `armada admin ls` lists the names on record, whether they are removed, who
  added them, and which one is the caller.
- Every API call and every metrics scrape with an administrator certificate
  checks the record (`AdminAllowed`): no record accepts the certificate, a
  removed name refuses it, and so does a certificate that starts before
  `Since`. The check is one read of one key, like the one for node
  certificates.
- `armadad init` records the first administrator, named after the user
  who ran it through sudo (else the current user), and `armada admin renew`
  records a caller who is not on record yet, both accepting every
  certificate of the name, so administrators show up in the list without
  losing access.
- Only administrators call these methods. Automation identities never can
  (default deny), nor can node, server, or metrics certificates.

## Consequences

- The audit log names the person, and access is taken back per person
  without touching anyone else's certificate.
- Names that are not on record keep working: clusters from before this
  change keep their administrators until they renew, are removed, or are
  added again.
- Certificate start times are whole seconds: a certificate of the same name
  issued in the same second as the new one is not told apart. Only an
  administrator, or root with the CA key, can issue one.
- Root on a server holds the CA key and can always issue certificates
  (`armadad admin renew`), but not for a removed name: the record refuses
  them.
- Servers on an older schema do not know the records, so the schema step
  keeps them from leading once any server runs this version (ADR 0012).
