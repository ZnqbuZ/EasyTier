use std::ffi::{CString, c_char, c_int};

use easytier::common::config::{ConfigFileControl, TomlConfigLoader};

use crate::{
    config_server::{in_config_server_callback, wait_for_config_server_delivery},
    error::set_error_msg,
    state::{ffi_context, resolve_instance_id_by_name},
    types::KeyValuePair,
};

/// # Safety
/// Set the tun fd.
///
/// A positive `fd` requires a non-null, valid snapshot UUID and a live named
/// instance; the call waits for the complete local attachment. A non-positive
/// `fd` only releases local borrows through the existing detach path and does
/// not require the name to remain running. It never claims the system VPN was
/// closed.
pub(crate) unsafe fn set_tun_fd(
    inst_name: *const c_char,
    fd: c_int,
    snapshot_id: *const c_char,
) -> c_int {
    let result = (|| -> Result<(), String> {
        let inst_name = unsafe { crate::strings::c_str_to_string(inst_name, "instance_name") }?;
        cfg_select! {
            any(target_os = "android", target_os = "ios", target_env = "ohos", all(target_os = "macos", feature = "macos-ne")) => {
                if fd > 0 {
                    let snapshot = unsafe { crate::strings::c_str_to_string(snapshot_id, "snapshot_id") }?;
                    let snapshot = uuid::Uuid::parse_str(&snapshot)
                        .map_err(|error| format!("invalid snapshot_id: {error}"))?;
                    let instance_id = resolve_instance_id_by_name(&inst_name)?
                        .ok_or_else(|| format!("instance not found: {inst_name}"))?;
                    let config = ffi_context()
                        .runtime
                        .block_on(easytier::instance::factory::attach_mobile_tun_fd(
                            ffi_context().manager.as_ref(),
                            fd,
                            Some(std::slice::from_ref(&instance_id)),
                            Some(snapshot),
                        ))
                        .map_err(|error| error.to_string())?;
                    if !config.instance_ids.contains(&instance_id) {
                        return Err(format!(
                            "instance {inst_name} is not part of the attached mobile configuration"
                        ));
                    }
                    Ok(())
                } else {
                    // The host may have already removed the named instance.
                    // Release every surviving local borrow through the existing
                    // complete-table detach path instead of resolving the name.
                    ffi_context()
                        .runtime
                        .block_on(easytier::instance::factory::attach_mobile_tun_fd(
                            ffi_context().manager.as_ref(),
                            fd,
                            None,
                            None,
                        ))
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                }
            },
            _ => {
                let _ = snapshot_id;
                let instance_id = resolve_instance_id_by_name(&inst_name)?
                    .ok_or_else(|| format!("instance not found: {inst_name}"))?;
                ffi_context()
                    .manager
                    .attach_tun_fd(instance_id, fd)
                    .map_err(|error| error.to_string())
            },
        }
    })();

    match result {
        Ok(()) => 0,
        Err(error) => {
            set_error_msg(&format!("failed to set tun fd: {error}"));
            -1
        }
    }
}

/// Returns the complete configuration the local VPN owner must install before
/// attaching. A valid name that no longer has a live instance exports the
/// normalized empty table; malformed input, ambiguous names and real query
/// failures return `NULL` with the last error set.
pub(crate) unsafe fn get_mobile_tun_config(inst_name: *const c_char) -> *mut c_char {
    let result = (|| -> Result<String, String> {
        let name = unsafe { crate::strings::c_str_to_string(inst_name, "instance_name") }?;
        cfg_select! {
            any(target_os = "android", target_os = "ios", target_env = "ohos", all(target_os = "macos", feature = "macos-ne")) => {
                // None is the explicit empty participation range. It lets a
                // stopping host re-read the complete result and converge
                // without treating the absence of a live run as a query error.
                let scope = resolve_instance_id_by_name(&name)?.into_iter().collect::<Vec<_>>();
                let config = ffi_context()
                    .runtime
                    .block_on(easytier::instance::factory::get_mobile_tun_config(
                        ffi_context().manager.as_ref(),
                        &scope,
                    ))
                    .map_err(|error| error.to_string())?;
                serde_json::to_string(&config).map_err(|error| error.to_string())
            },
            _ => {
                let _ = resolve_instance_id_by_name(&name)?
                    .ok_or_else(|| format!("instance not found: {name}"))?;
                Err("system VPN configuration is unavailable on this target".to_owned())
            },
        }
    })();
    match result.and_then(|json| CString::new(json).map_err(|error| error.to_string())) {
        Ok(json) => json.into_raw(),
        Err(error) => {
            set_error_msg(&error);
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// Parse the config
pub(crate) unsafe fn parse_config(cfg_str: *const std::ffi::c_char) -> std::ffi::c_int {
    let cfg_str = unsafe {
        assert!(!cfg_str.is_null());
        std::ffi::CStr::from_ptr(cfg_str)
            .to_string_lossy()
            .into_owned()
    };

    if let Err(e) = TomlConfigLoader::new_from_str(&cfg_str) {
        set_error_msg(&format!("failed to parse config: {:?}", e));
        return -1;
    }

    0
}

/// # Safety
/// Run the network instance
pub(crate) unsafe fn run_network_instance(cfg_str: *const std::ffi::c_char) -> std::ffi::c_int {
    if in_config_server_callback() {
        set_error_msg("cannot run network instance from config server callback");
        return -1;
    }

    let cfg_str = unsafe {
        assert!(!cfg_str.is_null());
        std::ffi::CStr::from_ptr(cfg_str)
            .to_string_lossy()
            .into_owned()
    };
    let cfg = match TomlConfigLoader::new_from_str(&cfg_str) {
        Ok(cfg) => cfg,
        Err(e) => {
            set_error_msg(&format!("failed to parse config: {}", e));
            return -1;
        }
    };

    wait_for_config_server_delivery();
    if let Err(e) = ffi_context().runtime.block_on(
        ffi_context()
            .process_management
            .run_owned_network_instance(cfg, ConfigFileControl::STATIC_CONFIG),
    ) {
        set_error_msg(&format!("failed to start instance: {}", e));
        return -1;
    }

    0
}

unsafe fn parse_instance_names(
    inst_names: *const *const c_char,
    length: usize,
) -> Option<Vec<String>> {
    if length == 0 {
        return Some(Vec::new());
    }
    if inst_names.is_null() {
        set_error_msg("inst_names is null");
        return None;
    }

    let names = unsafe { std::slice::from_raw_parts(inst_names, length) };
    let mut parsed = Vec::with_capacity(length);
    for (index, &name) in names.iter().enumerate() {
        if name.is_null() {
            set_error_msg(&format!("inst_names[{}] is null", index));
            return None;
        }
        parsed.push(
            unsafe { std::ffi::CStr::from_ptr(name) }
                .to_string_lossy()
                .into_owned(),
        );
    }
    Some(parsed)
}

/// # Safety
/// Retain the network instance
pub(crate) unsafe fn retain_network_instance(
    inst_names: *const *const std::ffi::c_char,
    length: usize,
) -> std::ffi::c_int {
    if in_config_server_callback() {
        set_error_msg("cannot retain network instances from config server callback");
        return -1;
    }

    wait_for_config_server_delivery();
    let retained_names = if length == 0 {
        Vec::new()
    } else {
        let Some(inst_names) = (unsafe { parse_instance_names(inst_names, length) }) else {
            return -1;
        };
        inst_names
    };

    if let Err(error) = ffi_context().runtime.block_on(
        ffi_context()
            .process_management
            .retain_owned_network_instances_by_name(retained_names),
    ) {
        set_error_msg(&format!("failed to retain instances: {error}"));
        return -1;
    }

    0
}

/// # Safety
/// Delete named network instances.
pub(crate) unsafe fn delete_network_instance(
    inst_names: *const *const std::ffi::c_char,
    length: usize,
) -> std::ffi::c_int {
    if in_config_server_callback() {
        set_error_msg("cannot delete network instances from config server callback");
        return -1;
    }

    wait_for_config_server_delivery();
    if length == 0 {
        return 0;
    }

    let Some(inst_names) = (unsafe { parse_instance_names(inst_names, length) }) else {
        return -1;
    };

    if let Err(error) = ffi_context().runtime.block_on(
        ffi_context()
            .process_management
            .delete_owned_network_instances_by_name(inst_names),
    ) {
        set_error_msg(&format!("failed to delete instances: {error}"));
        return -1;
    }

    0
}

/// # Safety
/// Collect the network infos
pub(crate) unsafe fn collect_network_infos(
    infos: *mut KeyValuePair,
    max_length: usize,
) -> std::ffi::c_int {
    if in_config_server_callback() {
        set_error_msg("cannot collect network infos from config server callback");
        return -1;
    }

    if max_length == 0 {
        return 0;
    }

    let infos = unsafe {
        assert!(!infos.is_null());
        std::slice::from_raw_parts_mut(infos, max_length)
    };

    let collected_infos = match ffi_context().manager.collect_network_infos_sync() {
        Ok(infos) => infos,
        Err(e) => {
            set_error_msg(&format!("failed to collect network infos: {}", e));
            return -1;
        }
    };

    let mut index = 0;
    for (instance_id, value) in collected_infos.iter() {
        if index >= max_length {
            break;
        }
        let Some(key) = ffi_context()
            .manager
            .instance(*instance_id)
            .map(|instance| instance.instance_name().to_owned())
        else {
            continue;
        };
        // convert value to json string
        let value = match serde_json::to_string(&value) {
            Ok(value) => value,
            Err(e) => {
                set_error_msg(&format!("failed to serialize instance info: {}", e));
                return -1;
            }
        };

        infos[index] = KeyValuePair {
            key: std::ffi::CString::new(key).unwrap().into_raw(),
            value: std::ffi::CString::new(value).unwrap().into_raw(),
        };
        index += 1;
    }

    index as std::ffi::c_int
}

/// # Safety
/// List the instance names and IDs known by the FFI instance manager.
pub(crate) unsafe fn list_instance(infos: *mut KeyValuePair, max_length: usize) -> std::ffi::c_int {
    if in_config_server_callback() {
        set_error_msg("cannot list instances from config server callback");
        return -1;
    }

    if max_length == 0 {
        return 0;
    }

    if infos.is_null() {
        set_error_msg("infos is null");
        return -1;
    }

    let infos = unsafe { std::slice::from_raw_parts_mut(infos, max_length) };
    let mut instances = ffi_context()
        .manager
        .instance_ids()
        .into_iter()
        .filter_map(|id| {
            ffi_context()
                .manager
                .instance(id)
                .map(|instance| (instance.instance_name().to_owned(), id))
        })
        .collect::<Vec<_>>();
    instances.sort_by(|(left_name, left_id), (right_name, right_id)| {
        left_name
            .cmp(right_name)
            .then_with(|| left_id.to_string().cmp(&right_id.to_string()))
    });

    let encoded_instances = match instances
        .into_iter()
        .take(max_length)
        .map(|(name, id)| {
            let key = CString::new(name)
                .map_err(|err| format!("failed to encode instance name: {}", err))?;
            let value = CString::new(id.to_string())
                .map_err(|err| format!("failed to encode instance id: {}", err))?;
            Ok((key, value))
        })
        .collect::<Result<Vec<_>, String>>()
    {
        Ok(value) => value,
        Err(err) => {
            set_error_msg(&err);
            return -1;
        }
    };

    let count = encoded_instances.len();
    for (index, (key, value)) in encoded_instances.into_iter().enumerate() {
        infos[index] = KeyValuePair {
            key: key.into_raw(),
            value: value.into_raw(),
        };
    }

    count as std::ffi::c_int
}
