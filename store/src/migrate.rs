//! The schema and its migrations (etcd.go). migrations[i] moves schema
//! i+1 to i+2; most steps rewrite nothing and exist so that servers that
//! would drop or misread a new field can no longer lead (ADR 0012).

use crate::access::{migrate_access, migrate_users};
use crate::error::{Result, other};
use crate::metrics::migrate_metrics;
use crate::spaces::migrate_spaces;
use crate::tx::*;

/// One step: what it rewrites.
#[derive(Clone, Copy, Debug)]
enum Step {
    Nothing,
    Access,
    Spaces,
    Metrics,
    Users,
}

const MIGRATIONS: [Step; (SCHEMA - 1) as usize] = [
    Step::Nothing, // 1 -> 2: node labels, restricted, os, arch (ADR 0014)
    Step::Nothing, // 2 -> 3: jobs (ADR 0019)
    Step::Nothing, // 3 -> 4: traffic splitting (ADR 0022)
    Step::Nothing, // 4 -> 5: volumes (ADR 0023)
    Step::Nothing, // 5 -> 6: the cluster network (ADR 0025)
    Step::Nothing, // 6 -> 7: spaces (ADR 0026)
    Step::Nothing, // 7 -> 8: administrators on record (ADR 0028)
    Step::Access,  // 8 -> 9: users and services (ADR 0033)
    Step::Nothing, // 9 -> 10: init containers and sidecars (ADR 0038)
    Step::Spaces,  // 10 -> 11: projects are called spaces
    Step::Nothing, // 11 -> 12: job runs split into tasks
    Step::Metrics, // 12 -> 13: metrics certificates on record
    Step::Users,   // 13 -> 14: unrecorded users and the cutoff
    Step::Nothing, // 14 -> 15: secrets of the space (ADR 0052)
];

async fn run(step: Step, t: &mut Etx<'_>) -> Result<()> {
    match step {
        Step::Nothing => Ok(()),
        Step::Access => migrate_access(t).await,
        Step::Spaces => migrate_spaces(t).await,
        Step::Metrics => migrate_metrics(t).await,
        Step::Users => migrate_users(t).await,
    }
}

impl Etcd {
    /// StoredSchema returns the schema the keyspace is written in.
    pub async fn stored_schema(&self) -> Result<i64> {
        let mut v = 0;
        view!(self, |t| {
            v = t.get::<i64>(KEY_SCHEMA).await?.unwrap_or(0);
            Ok(())
        })?;
        Ok(v)
    }

    /// Migrate brings the keyspace to this crate's schema, one step per
    /// transaction, and returns the schema it started from. Only the
    /// leader may call it, on a store fenced to its term, once every server
    /// understands the new schema (ADR 0012).
    pub async fn migrate(&self) -> Result<i64> {
        self.migrate_to(SCHEMA).await
    }

    /// Migrate to schema target (tests stop on the way).
    pub async fn migrate_to(&self, target: i64) -> Result<i64> {
        let from = self.stored_schema().await?;
        if from > target {
            return Err(other!(
                "the state was written by a newer Armada (schema {from}, this binary knows {target})"
            ));
        }
        for v in from..target {
            tx!(self, |t| {
                let cur = t.get::<i64>(KEY_SCHEMA).await?.unwrap_or(0);
                if cur != v {
                    return Err(other!(
                        "store: schema changed to {cur} during migration from {v}"
                    ));
                }
                let step = MIGRATIONS
                    .get((v - 1) as usize)
                    .copied()
                    .ok_or_else(|| other!("store: no migration from schema {v}"))?;
                run(step, t)
                    .await
                    .map_err(|e| e.context(format!("migrate schema {v} to {}", v + 1)))?;
                t.put(KEY_SCHEMA, &(v + 1))
            })?;
        }
        Ok(from)
    }
}
