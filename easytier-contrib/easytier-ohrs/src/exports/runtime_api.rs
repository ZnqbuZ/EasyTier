use crate::config::repository::{clear_runtime_config_snapshot, get_runtime_config_snapshot};
use crate::config::types::stored_config::KeyValuePair;
use crate::kernel_bridge::{
    start_local_socket_server as start_local_socket_server_inner,
    stop_local_socket_server as stop_local_socket_server_inner,
};
use crate::runtime::state::runtime_state::{
    RuntimeAggregateState, RuntimeInstanceState, TunAggregateState, clear_tun_attached,
    is_tun_attached, mark_tun_attached, runtime_instance_from_config_snapshot,
    runtime_instance_from_running_info,
};
use crate::{ASYNC_RUNTIME, INSTANCE_MANAGER, WEB_CLIENTS};
use easytier::instance::factory::MobileTunConfig;

pub(crate) fn start_kernel(
    config_id: String,
    start_kernel_with_config_id: impl Fn(&str) -> bool,
) -> bool {
    start_kernel_with_config_id(&config_id)
}

pub(crate) fn stop_kernel(
    config_id: String,
    stop_web_client: impl Fn(&str) -> bool,
    parse_instance_uuid: impl Fn(&str) -> Option<uuid::Uuid>,
    maybe_stop_local_socket_server: impl Fn(),
) -> bool {
    if stop_web_client(&config_id) {
        clear_tun_attached(&config_id);
        clear_runtime_config_snapshot(&config_id);
        return true;
    }

    let _ = stop_local_socket_server_inner();

    let Some(instance_id) = parse_instance_uuid(&config_id) else {
        return false;
    };

    let ret = ASYNC_RUNTIME
        .block_on(INSTANCE_MANAGER.delete_network_instances([instance_id]))
        .map(|_| true)
        .unwrap_or_else(|err| {
            ohrs_log_error!("[Rust] stop_kernel failed {}: {}", config_id, err);
            false
        });
    if ret {
        clear_tun_attached(&config_id);
        clear_runtime_config_snapshot(&config_id);
    }
    let has_active_instances = !INSTANCE_MANAGER.instance_ids().is_empty();
    let has_web_clients = WEB_CLIENTS
        .lock()
        .map(|guard| !guard.is_empty())
        .unwrap_or(false);
    if has_active_instances || has_web_clients {
        let _ = start_local_socket_server_inner();
    }
    maybe_stop_local_socket_server();
    ret
}

pub(crate) fn stop_network_instance(
    config_ids: Vec<String>,
    stop_kernel: impl Fn(String) -> bool,
) -> bool {
    let mut ok = true;
    for config_id in config_ids {
        ok = stop_kernel(config_id) && ok;
    }
    ok
}

pub(crate) fn collect_network_infos() -> Vec<KeyValuePair> {
    let infos = match ASYNC_RUNTIME.block_on(INSTANCE_MANAGER.collect_network_infos()) {
        Ok(infos) => infos,
        Err(err) => {
            ohrs_log_error!("[Rust] collect network infos failed {}", err);
            return vec![];
        }
    };

    infos
        .into_iter()
        .filter_map(|(key, value)| {
            serde_json::to_string(&value)
                .ok()
                .map(|value_json| KeyValuePair {
                    key: key.to_string(),
                    value: value_json,
                })
        })
        .collect()
}

pub(crate) fn set_tun_fd(
    config_id: String,
    fd: i32,
    snapshot_id: Option<String>,
    parse_instance_uuid: impl Fn(&str) -> Option<uuid::Uuid>,
) -> bool {
    let Some(instance_id) = parse_instance_uuid(&config_id) else {
        ohrs_log_error!("[Rust] set_tun_fd invalid instance id: {}", config_id);
        return false;
    };

    #[cfg(target_env = "ohos")]
    let result = {
        let snapshot = match snapshot_id.map(|id| uuid::Uuid::parse_str(&id)).transpose() {
            Ok(id) => id,
            Err(error) => {
                ohrs_log_error!("[Rust] invalid VPN snapshot: {}", error);
                return false;
            }
        };
        ASYNC_RUNTIME
            .block_on(easytier::instance::factory::attach_mobile_tun_fd(
                INSTANCE_MANAGER.as_ref(),
                fd,
                Some(&[instance_id]),
                snapshot,
            ))
            .and_then(|config| {
                if fd > 0 && !config.instance_ids.contains(&instance_id) {
                    anyhow::bail!(
                        "instance {} is not part of the attached mobile configuration",
                        config_id
                    );
                }
                Ok(())
            })
    };
    #[cfg(not(target_env = "ohos"))]
    let result = {
        let _ = snapshot_id;
        INSTANCE_MANAGER.attach_tun_fd(instance_id, fd)
    };
    result
        .map(|_| {
            if fd > 0 {
                mark_tun_attached(&config_id);
            } else {
                clear_tun_attached(&config_id);
            }
            true
        })
        .unwrap_or_else(|error| {
            // A failed positive attach or negative detach cannot leave a
            // previous success marker behind.
            clear_tun_attached(&config_id);
            ohrs_log_error!("[Rust] set_tun_fd failed {}: {}", config_id, error);
            false
        })
}

pub(crate) fn get_mobile_tun_config(
    config_id: String,
    parse_instance_uuid: impl Fn(&str) -> Option<uuid::Uuid>,
) -> Option<String> {
    let id = parse_instance_uuid(&config_id)?;
    cfg_select! {
        target_env = "ohos" => {
            let config = ASYNC_RUNTIME
                .block_on(easytier::instance::factory::get_mobile_tun_config(
                    INSTANCE_MANAGER.as_ref(),
                    &[id],
                ))
                .map_err(|error| {
                    ohrs_log_error!("[Rust] get mobile tun config failed {}: {error:#}", config_id);
                    error
                })
                .ok()?;
            serde_json::to_string(&config).ok()
        },
        _ => { let _ = id; None },
    }
}

fn current_mobile_config() -> anyhow::Result<MobileTunConfig> {
    #[cfg(target_env = "ohos")]
    {
        return ASYNC_RUNTIME
            .block_on(easytier::instance::factory::current_mobile_tun_config(
                INSTANCE_MANAGER.as_ref(),
            ))
            .map_err(|error| {
                anyhow::anyhow!("read current mobile TUN configuration failed: {error:#}")
            });
    }
    #[cfg(not(target_env = "ohos"))]
    {
        anyhow::bail!("current mobile TUN configuration is unavailable on this target")
    }
}

fn runtime_aggregate_state(
    mut instances: Vec<RuntimeInstanceState>,
    mobile_config: MobileTunConfig,
) -> RuntimeAggregateState {
    instances.sort_by(|a, b| {
        a.display_name
            .cmp(&b.display_name)
            .then_with(|| a.instance_id.cmp(&b.instance_id))
    });
    let attached_instance_ids = instances
        .iter()
        .filter(|instance| instance.running && instance.tun_attached)
        .map(|instance| instance.instance_id.clone())
        .collect::<Vec<_>>();
    let running_instance_count =
        instances.iter().filter(|instance| instance.running).count() as i32;
    let tun_active = !attached_instance_ids.is_empty();
    RuntimeAggregateState {
        instances,
        tun: TunAggregateState {
            active: tun_active,
            attached_instance_ids,
            aggregated_routes: mobile_config.routes,
            dns_servers: mobile_config.dns.into_iter().collect(),
            need_rebuild: false,
        },
        running_instance_count,
    }
}

pub(crate) fn collect_runtime_state() -> anyhow::Result<RuntimeAggregateState> {
    let infos = ASYNC_RUNTIME
        .block_on(INSTANCE_MANAGER.collect_network_infos())
        .map_err(|error| anyhow::anyhow!("collect network infos failed: {error:#}"))?;
    let mobile_config = current_mobile_config()?;
    let mut live_infos = infos
        .into_iter()
        .map(|(instance_id, info)| (instance_id.to_string(), info))
        .collect::<std::collections::HashMap<_, _>>();
    let mut active_config_ids = live_infos.keys().cloned().collect::<Vec<_>>();
    if let Ok(guard) = WEB_CLIENTS.lock() {
        for config_id in guard.keys() {
            if !active_config_ids.iter().any(|value| value == config_id) {
                active_config_ids.push(config_id.clone());
            }
        }
    }

    let mut instances = Vec::with_capacity(active_config_ids.len());
    for config_id in active_config_ids {
        if let Some(info) = live_infos.remove(&config_id) {
            let snapshot = get_runtime_config_snapshot(&config_id);
            let display_name = snapshot
                .as_ref()
                .map(|snapshot| snapshot.display_name.clone())
                .unwrap_or_else(|| config_id.clone());
            instances.push(runtime_instance_from_running_info(
                config_id,
                display_name,
                snapshot.map(|snapshot| snapshot.config),
                info,
            ));
        } else if let Some(snapshot) = get_runtime_config_snapshot(&config_id) {
            instances.push(runtime_instance_from_config_snapshot(
                config_id,
                snapshot.display_name,
                snapshot.config,
                true,
            ));
        } else {
            let tun_attached = is_tun_attached(&config_id);
            instances.push(RuntimeInstanceState {
                config_id: config_id.clone(),
                instance_id: config_id.clone(),
                display_name: config_id.clone(),
                running: true,
                tun_required: tun_attached,
                tun_attached,
                magic_dns_enabled: false,
                need_exit_node: false,
                error_message: None,
                my_node_info: None,
                events: Vec::new(),
                routes: Vec::new(),
                peers: Vec::new(),
                manual_routes: Vec::new(),
            });
        }
    }

    Ok(runtime_aggregate_state(instances, mobile_config))
}


