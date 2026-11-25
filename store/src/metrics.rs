//! Metrics scrapers' certificates (metrics.go, ADR 0017).

use armada_spec::gotime::Time;

use crate::access::MAX_SERVICE_CERTS;
use crate::error::Result;
use crate::gojson::{decode, from_ms, unix_milli};
use crate::records::{CertRec, MetricsRec};
use crate::tx::*;
use crate::types::*;

pub(crate) const PFX_METRICS: &str = "metrics/";
pub(crate) const KEY_METRICS_CUTOFF: &str = "meta/metrics-cutoff";

/// migrateMetrics (schema 12 -> 13) records when metrics certificates
/// started being recorded.
pub(crate) async fn migrate_metrics(t: &mut Etx<'_>) -> Result<()> {
    let now = unix_milli(&t.s.now());
    t.put(KEY_METRICS_CUTOFF, &now)
}

impl Etcd {
    /// RecordMetricsCert records a certificate issued to the scraper name.
    pub async fn record_metrics_cert(&self, name: &str, c: &NodeCert, actor: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            let k = format!("{PFX_METRICS}{name}");
            let mut r = t
                .get::<MetricsRec>(&k)
                .await?
                .unwrap_or_else(|| MetricsRec {
                    name: name.to_string(),
                    certs: Vec::new(),
                });
            let mut certs: Vec<CertRec> = r
                .certs
                .iter()
                .filter(|o| o.not_after > unix_milli(&now))
                .cloned()
                .collect();
            certs.push(CertRec {
                serial: c.serial.clone(),
                not_after: unix_milli(&c.not_after),
                created_at: unix_milli(&now),
                ..Default::default()
            });
            if certs.len() > MAX_SERVICE_CERTS {
                certs.drain(..certs.len() - MAX_SERVICE_CERTS);
            }
            r.certs = certs;
            t.put(&k, &r)?;
            t.audit(
                &now,
                actor,
                "metrics.certificate",
                name,
                &format!("serial={}", c.serial),
            )
            .await
        })
    }

    /// RevokeMetricsCerts refuses every certificate of the scraper name.
    pub async fn revoke_metrics_certs(&self, name: &str, actor: &str) -> Result<()> {
        let now = self.now();
        tx!(self, |t| {
            t.put(
                &format!("{PFX_METRICS}{name}"),
                &MetricsRec {
                    name: name.to_string(),
                    certs: Vec::new(),
                },
            )?;
            t.audit(&now, actor, "metrics.revoke", name, "").await
        })
    }

    /// ListMetricsCerts returns the scrapers with an unexpired certificate
    /// on record, by name.
    pub async fn list_metrics_certs(&self) -> Result<Vec<MetricsCredential>> {
        let now = unix_milli(&self.now());
        let mut out = Vec::new();
        view!(self, |t| {
            out.clear();
            for (k, v) in t.list(PFX_METRICS).await? {
                let r: MetricsRec = decode(&k, &v)?;
                let certs: Vec<NodeCert> = r
                    .certs
                    .iter()
                    .filter(|c| c.not_after > now)
                    .map(|c| NodeCert {
                        serial: c.serial.clone(),
                        not_after: from_ms(c.not_after),
                    })
                    .collect();
                if !certs.is_empty() {
                    out.push(MetricsCredential {
                        name: k.strip_prefix(PFX_METRICS).unwrap_or(&k).to_string(),
                        certs,
                    });
                }
            }
            Ok(())
        })?;
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// MetricsAccess reports whether a metrics certificate is accepted.
    pub async fn metrics_access(
        &self,
        name: &str,
        not_before: &Time,
        serial: &str,
    ) -> Result<bool> {
        let mut allowed = false;
        view!(self, |t| {
            if let Some(r) = t.get::<MetricsRec>(&format!("{PFX_METRICS}{name}")).await? {
                let now = unix_milli(&self.now());
                allowed = r
                    .certs
                    .iter()
                    .any(|c| c.serial == serial && c.not_after > now);
                return Ok(());
            }
            if let Some(cutoff) = t.get::<i64>(KEY_METRICS_CUTOFF).await? {
                allowed = unix_milli(not_before) < cutoff;
                return Ok(());
            }
            allowed = t.get::<i64>(KEY_SCHEMA).await?.unwrap_or(0) < 13;
            Ok(())
        })?;
        Ok(allowed)
    }
}
