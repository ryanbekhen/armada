//! Spaces (ADR 0026; Go's spaces.go).

use std::collections::HashMap;

use armada_proto::armada::v1::*;
use armada_spec::validate::{DEFAULT_SPACE, split_app_id, valid_space};
use armada_store::Kind;
use tonic::{Code, Status};

use crate::events::timestamp;
use crate::grpc::Auth;
use crate::{Server, store_err};

fn space_info(p: &armada_store::Space, apps: i32) -> SpaceInfo {
    SpaceInfo {
        name: p.name.clone(),
        created_by: p.created_by.clone(),
        apps,
        created_at: (!p.created_at.is_zero()).then(|| timestamp(&p.created_at)),
        network_isolation: false,
    }
}

impl Server {
    /// Whether the default space and the others are isolated.
    async fn isolation(&self) -> Result<(bool, bool), armada_store::Error> {
        match self.store().get_network().await {
            Err(e) if e.kind == Kind::NotFound => Ok((false, false)),
            Err(e) => Err(e),
            Ok(n) => Ok((n.isolate_default, true)),
        }
    }

    async fn isolated(&self, space: &str) -> Result<bool, armada_store::Error> {
        let (def, others) = self.isolation().await?;
        Ok(if space == DEFAULT_SPACE { def } else { others })
    }

    /// CreateSpace records a new space.
    pub(crate) async fn create_space(
        &self,
        a: &Auth,
        req: CreateSpaceRequest,
    ) -> Result<SpaceInfo, Status> {
        if !valid_space(&req.name) {
            return Err(Status::new(
                Code::InvalidArgument,
                "invalid space name: use lowercase letters, digits, and single hyphens, starting with a letter, at most 30 characters",
            ));
        }
        if !a.acc.creates() {
            return Err(Status::new(
                Code::PermissionDenied,
                format!("{} may not create spaces", a.acc.id),
            ));
        }
        // Whoever creates a space without cluster-admin becomes its admin.
        let by = if a.acc.admin() {
            None
        } else {
            a.acc.p.as_ref()
        };
        let p = self
            .store()
            .create_space(&req.name, &a.actor(), by)
            .await
            .map_err(|e| store_err(&e))?;
        self.0.log.info(
            "space created",
            &[("space", req.name.clone()), ("by", a.actor())],
        );
        let mut info = space_info(&p, 0);
        info.network_isolation = self.isolated(&req.name).await.map_err(|e| store_err(&e))?;
        Ok(info)
    }

    /// ListSpaces lists every space with the number of apps and jobs in it.
    pub(crate) async fn list_spaces(
        &self,
        a: &Auth,
        _req: ListSpacesRequest,
    ) -> Result<ListSpacesResponse, Status> {
        let ps = self
            .store()
            .list_spaces()
            .await
            .map_err(|e| store_err(&e))?;
        let ids = self
            .store()
            .list_app_ids()
            .await
            .map_err(|e| store_err(&e))?;
        let mut count: HashMap<String, i32> = HashMap::new();
        for id in ids {
            if let Some((p, _)) = split_app_id(&id) {
                *count.entry(p).or_default() += 1;
            }
        }
        let (def, others) = self.isolation().await.map_err(|e| store_err(&e))?;
        let mut out = ListSpacesResponse::default();
        for p in ps {
            if a.acc.space(&p.name).is_err() {
                continue;
            }
            let mut info = space_info(&p, count.get(&p.name).copied().unwrap_or(0));
            info.network_isolation = if p.name == DEFAULT_SPACE { def } else { others };
            out.spaces.push(info);
        }
        Ok(out)
    }

    /// UpdateSpace changes the default space's network isolation.
    pub(crate) async fn update_space(
        &self,
        a: &Auth,
        req: UpdateSpaceRequest,
    ) -> Result<SpaceInfo, Status> {
        let name = if req.name.is_empty() {
            DEFAULT_SPACE.to_string()
        } else {
            req.name.clone()
        };
        if !valid_space(&name) {
            return Err(Status::new(Code::InvalidArgument, "invalid space name"));
        }
        if !a.acc.admin() {
            return Err(Status::new(
                Code::PermissionDenied,
                "only cluster-admin changes space settings",
            ));
        }
        if req.network_isolation == Some(false) && name != DEFAULT_SPACE {
            return Err(Status::new(
                Code::InvalidArgument,
                format!(
                    "space {name} is always isolated; only the default space can turn network isolation off"
                ),
            ));
        }
        let p = self
            .store()
            .get_space(&name)
            .await
            .map_err(|e| store_err(&e))?;
        if let Some(on) = req.network_isolation
            && name == DEFAULT_SPACE
        {
            self.store()
                .set_default_isolation(on, &a.actor())
                .await
                .map_err(|e| store_err(&e))?;
            self.0.log.info(
                "default space network isolation changed",
                &[("on", on.to_string()), ("by", a.actor())],
            );
            self.trigger();
        }
        let mut info = space_info(&p, 0);
        info.network_isolation = self.isolated(&name).await.map_err(|e| store_err(&e))?;
        Ok(info)
    }

    /// DeleteSpace removes an empty space.
    pub(crate) async fn delete_space(
        &self,
        a: &Auth,
        req: DeleteSpaceRequest,
    ) -> Result<DeleteSpaceResponse, Status> {
        if !valid_space(&req.name) {
            return Err(Status::new(Code::InvalidArgument, "invalid space name"));
        }
        a.acc.space(&req.name)?;
        if !a.acc.creates() {
            return Err(Status::new(
                Code::PermissionDenied,
                format!("{} may not delete spaces", a.acc.id),
            ));
        }
        self.store()
            .delete_space(&req.name, &a.actor())
            .await
            .map_err(|e| store_err(&e))?;
        self.0.usage.forget_space(&req.name);
        self.0.log.info(
            "space removed",
            &[("space", req.name.clone()), ("by", a.actor())],
        );
        Ok(DeleteSpaceResponse {})
    }
}
