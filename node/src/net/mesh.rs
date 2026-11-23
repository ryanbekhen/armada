//! `mesh.json` (mesh.go): the last peer list a node with peers on WireGuard
//! between endpoints applied, kept so the tunnels come up before the control
//! plane. It holds a NetworkConfig in protojson with only the mode, ranges,
//! and peers, owner-only (0600).

use super::config::NetworkConfig;
use super::key::{read_private_file, write_file_atomic};
use std::io;
use std::path::Path;

/// maxMeshCache bounds the file read back.
const MAX_MESH_CACHE: usize = 4 << 20;

/// meshCacheOf: what the file keeps of a configuration.
pub fn cache_of(cfg: &NetworkConfig) -> NetworkConfig {
    NetworkConfig {
        mode: cfg.mode.clone(),
        cluster_cidr: cfg.cluster_cidr.clone(),
        mesh_cidr: cfg.mesh_cidr.clone(),
        peers: cfg.peers.clone(),
        ..NetworkConfig::default()
    }
}

/// loadMeshCache: the kept list, or None when there is none.
pub fn load(path: &Path) -> Result<Option<NetworkConfig>, String> {
    let data = match read_private_file(path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if data.len() > MAX_MESH_CACHE {
        return Err(format!(
            "{}: larger than {MAX_MESH_CACHE} bytes",
            path.display()
        ));
    }
    serde_json::from_slice(&data)
        .map(Some)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// saveMeshCache: writes the peer list of cfg, unless the file holds it.
pub fn save(path: &Path, cfg: &NetworkConfig) -> Result<(), String> {
    let keep = cache_of(cfg);
    if let Ok(Some(old)) = load(path)
        && old == keep
    {
        return Ok(());
    }
    let mut data = serde_json::to_vec_pretty(&keep).map_err(|e| e.to_string())?;
    data.push(b'\n');
    write_file_atomic(path, &data, 0o600).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::config::{NetworkEndpoint, NetworkPeer, U32};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn keeps_the_peers() {
        let dir = std::env::temp_dir().join(format!("armada-node-mesh-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mesh.json");
        assert_eq!(load(&path).unwrap(), None);
        let full = NetworkConfig {
            mode: "mesh".into(),
            cluster_cidr: "10.120.0.0/16".into(),
            mesh_cidr: "10.121.0.0/16".into(),
            peers: vec![NetworkPeer {
                node: "a".into(),
                private_ip: "10.121.0.1".into(),
                subnet: "10.120.0.0/24".into(),
                endpoint: "203.0.113.1".into(),
                ..Default::default()
            }],
            endpoints: vec![NetworkEndpoint {
                address: "10.120.0.5".into(),
                app: "web".into(),
            }],
            tcp_ports: vec![U32(5432)],
            ..Default::default()
        };
        save(&path, &full).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(load(&path).unwrap(), Some(cache_of(&full)));
        let before = fs::metadata(&path).unwrap().modified().unwrap();
        save(&path, &full).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&path).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
