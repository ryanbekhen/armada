//! The node's connection tracking table (ADR 0025; Go's usage.go
//! sampleConntrack and internal/conntrack): raised to its target with
//! every sample, its use reported. [`NodeConntrack`] runs armada-node's
//! `conntrack read|raise`, as Go's Table.WithProgram does.

use std::time::Duration;

use serde_json::json;

use super::nodeprog;
use crate::agent::Inner;
use crate::proxy::BoxFut;
use crate::runtime::Runtime;

/// Where the kernel keeps the table's numbers.
pub const PROC_DIR: &str = "/proc/sys/net/netfilter";
/// One call's bound.
const PROGRAM_TIMEOUT: Duration = Duration::from_secs(10);

/// The node's connection tracking table.
pub trait Conntrack: Send + Sync {
    /// Raises the limit to the node's target: the previous limit when it
    /// changed anything, else 0.
    fn raise(&self) -> BoxFut<'_, Result<i64, String>>;
    /// How many connections are tracked and the limit; None while the
    /// kernel module is not loaded.
    fn read(&self) -> BoxFut<'_, Option<(i64, i64)>>;
}

/// The table through armada-node.
pub struct NodeConntrack {
    pub bin: String,
    pub dir: String,
    /// The machine's memory the target follows; None: armada-node reads
    /// it.
    pub memory: Option<i64>,
}

impl NodeConntrack {
    fn request(&self) -> serde_json::Value {
        match self.memory {
            Some(m) => json!({"dir": self.dir, "memory": m}),
            None => json!({"dir": self.dir}),
        }
    }
}

impl Conntrack for NodeConntrack {
    fn raise(&self) -> BoxFut<'_, Result<i64, String>> {
        Box::pin(async move {
            let v = nodeprog::call(
                &self.bin,
                &["conntrack", "raise"],
                &self.request(),
                Some(PROGRAM_TIMEOUT),
            )
            .await?;
            Ok(v["previous"].as_i64().unwrap_or(0))
        })
    }

    fn read(&self) -> BoxFut<'_, Option<(i64, i64)>> {
        Box::pin(async move {
            let v = nodeprog::call(
                &self.bin,
                &["conntrack", "read"],
                &self.request(),
                Some(PROGRAM_TIMEOUT),
            )
            .await
            .ok()?;
            v["ok"].as_bool().filter(|ok| *ok)?;
            Some((v["entries"].as_i64()?, v["limit"].as_i64()?))
        })
    }
}

impl<R: Runtime> Inner<R> {
    /// Keeps the limit raised and adds the table's use to report
    /// (sampleConntrack); a failure to raise is a warning once.
    pub(crate) async fn sample_conntrack(
        &self,
        report: &mut armada_proto::armada::v1::UsageReport,
    ) {
        use std::sync::atomic::Ordering;
        let Some(t) = self.cfg.side.conntrack.clone() else {
            return;
        };
        match t.raise().await {
            Err(e) if !self.side.conntrack_warned.swap(true, Ordering::SeqCst) => {
                self.log
                    .warn("connection tracking limit not raised", &[("err", e)]);
            }
            Ok(previous) if previous > 0 => self.log.info(
                "raised the connection tracking limit",
                &[("previous", previous.to_string())],
            ),
            _ => {}
        }
        if let Some((entries, limit)) = t.read().await {
            report.conntrack_entries = entries;
            report.conntrack_max = limit;
        }
    }
}
