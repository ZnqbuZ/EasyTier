#[cfg(all(mobile, feature = "management-rpc"))]
use crate::instance::route::mobile::MobileTunConfig;
#[cfg(all(mobile, feature = "management-rpc"))]
use crate::instance::route::mobile::{
    MobileTunMember, MobileTunMemberError, config_for_members, select_members,
};

#[cfg(all(mobile, feature = "management-rpc"))]
use std::collections::BTreeSet;

#[cfg(all(mobile, feature = "management-rpc"))]
use super::{NativeInstanceManager, NativeInstanceRuntimeHost};
#[cfg(all(mobile, feature = "management-rpc"))]
use crate::instance::shared_virtual_nic::SharedIfConfigClaims;
#[cfg(all(mobile, feature = "management-rpc"))]
use easytier_core::instance::CoreInstanceState;

#[cfg(all(mobile, feature = "management-rpc"))]
async fn collect_members(
    manager: &NativeInstanceManager,
    instance_ids: &[uuid::Uuid],
) -> (Vec<MobileTunMember>, Vec<MobileTunMemberError>) {
    let mut members = Vec::new();
    let mut rejected = Vec::new();
    let mut seen = BTreeSet::new();
    for &instance_id in instance_ids {
        if !seen.insert(instance_id) {
            continue;
        }
        let instance = manager.instance(instance_id);
        let runtime = instance
            .as_ref()
            .filter(|instance| instance.state() == CoreInstanceState::Running)
            .and_then(|instance| instance.runtime_host::<NativeInstanceRuntimeHost>())
            .filter(|runtime| runtime.tun_enabled());
        let Some(runtime) = runtime else {
            rejected.push(MobileTunMemberError {
                instance_id,
                error: "TUN-enabled instance is not running".to_owned(),
            });
            continue;
        };
        let (claims, current_claims, dns) = match runtime
            .mobile_tun_claims(&instance.as_ref().unwrap().packet_plane())
            .await
        {
            Ok(claims) => claims,
            Err(error) => {
                rejected.push(MobileTunMemberError {
                    instance_id,
                    error: error.to_string(),
                });
                continue;
            }
        };
        members.push(MobileTunMember::new(
            instance_id,
            runtime.instance_run_key(),
            claims,
            current_claims,
            dns,
        ));
    }
    (members, rejected)
}

#[cfg(all(mobile, feature = "management-rpc"))]
pub async fn get_mobile_tun_config(
    manager: &NativeInstanceManager,
    instance_ids: &[uuid::Uuid],
) -> MobileTunConfig {
    let (members, rejected) = collect_members(manager, instance_ids).await;
    let (members, rejected) = select_members(members, rejected);
    config_for_members(&members, rejected)
}

#[cfg(test)]
fn is_claim_conflict(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|error| error.is::<crate::instance::shared_virtual_nic::SharedIfConfigConflict>())
}

#[cfg(all(mobile, feature = "management-rpc"))]
pub async fn attach_mobile_tun_fd(
    manager: &NativeInstanceManager,
    fd: i32,
    instance_ids: Option<&[uuid::Uuid]>,
    snapshot_id: Option<uuid::Uuid>,
) -> anyhow::Result<MobileTunConfig> {
    let all_ids = manager
        .instances()
        .into_iter()
        .filter(|instance| {
            instance.state() == CoreInstanceState::Running
                && instance
                    .runtime_host::<NativeInstanceRuntimeHost>()
                    .is_some_and(NativeInstanceRuntimeHost::tun_enabled)
        })
        .map(|instance| instance.instance_id())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if fd <= 0 {
        let mut errors = Vec::new();
        for id in all_ids {
            if let Err(error) = attach_member(manager, id, 0, false, None, None).await {
                errors.push(error.to_string());
            }
        }
        anyhow::ensure!(
            errors.is_empty(),
            "failed to detach mobile TUN fd: {}",
            errors.join("; ")
        );
        return Ok(MobileTunConfig::default());
    }
    let (members, rejected) = collect_members(manager, instance_ids.unwrap_or(&all_ids)).await;
    let (members, rejected) = select_members(members, rejected);
    let config = config_for_members(&members, rejected);
    anyhow::ensure!(
        snapshot_id == Some(config.snapshot_id),
        "mobile TUN configuration changed; query and install a new snapshot before attaching"
    );
    let mut attached = Vec::new();
    // Open once; a rejected member never replaces or tears down this shared fd.
    for member in members {
        match attach_member(
            manager,
            member.instance_id,
            fd,
            attached.is_empty(),
            Some(member.run),
            Some(member.claims.clone()),
        )
        .await
        {
            Ok(()) => attached.push(member),
            Err(error) => {
                for id in &all_ids {
                    let _ = attach_member(manager, *id, 0, false, None, None).await;
                }
                return Err(error.context("failed to attach mobile TUN fd"));
            }
        }
    }
    Ok(config)
}

#[cfg(all(mobile, feature = "management-rpc"))]
async fn attach_member(
    manager: &NativeInstanceManager,
    instance_id: uuid::Uuid,
    fd: i32,
    replace_tun_fd: bool,
    expected_run: Option<uuid::Uuid>,
    claims: Option<SharedIfConfigClaims>,
) -> anyhow::Result<()> {
    let instance = manager
        .instance(instance_id)
        .ok_or_else(|| anyhow::anyhow!("instance {instance_id} is unavailable"))?;
    let runtime = instance
        .runtime_host::<NativeInstanceRuntimeHost>()
        .ok_or_else(|| anyhow::anyhow!("native runtime host is unavailable"))?;
    anyhow::ensure!(
        expected_run.is_none_or(|run| run == runtime.instance_run_key()),
        "instance restarted after its VPN configuration was prepared"
    );
    runtime
        .attach_mobile_tun_fd(fd, replace_tun_fd, claims)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::shared_virtual_nic::SharedIfConfig;

    #[test]
    fn distinguishes_claim_conflicts_from_device_failures_through_context() {
        let id = uuid::Uuid::from_u128(1);
        let mut claims = SharedIfConfig::default();
        claims.apply_member_claims(
            id,
            crate::instance::shared_virtual_nic::SharedIfConfigClaims {
                ipv4_addresses: std::collections::BTreeSet::from(["10.0.1.1/24".parse().unwrap()]),
                ..Default::default()
            },
        );
        let conflict = claims
            .ensure_disjoint(
                uuid::Uuid::from_u128(2),
                &crate::instance::shared_virtual_nic::SharedIfConfigClaims {
                    ipv4_addresses: std::collections::BTreeSet::from(["10.0.1.2/24"
                        .parse()
                        .unwrap()]),
                    ..Default::default()
                },
            )
            .unwrap_err();
        let error = anyhow::Error::new(crate::common::error::Error::from(conflict))
            .context("attach mobile TUN failed");
        assert!(is_claim_conflict(&error));
        assert!(!is_claim_conflict(&anyhow::Error::new(
            std::io::Error::from_raw_os_error(19)
        )));
    }
}
