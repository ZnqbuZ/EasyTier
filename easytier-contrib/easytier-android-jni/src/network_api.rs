use std::{
    ffi::{CStr, CString, c_char},
    ptr,
};

use easytier::proto::api::manage::{NetworkInstanceRunningInfo, NetworkInstanceRunningInfoMap};
use easytier_ffi::{
    KeyValuePair, collect_network_infos, delete_network_instance, free_string,
    get_mobile_tun_config, list_instance, parse_config, retain_network_instance,
    run_network_instance, set_tun_fd,
};
use jni::JNIEnv;
use jni::objects::{JClass, JObjectArray, JString};
use jni::sys::{jint, jstring};

use crate::{
    error::{get_last_error, throw_exception},
    strings::{jstring_to_cstring, optional_jstring_to_cstring},
};

/// Select the native snapshot pointer for one JNI setTunFd call.
///
/// A positive FD requires a snapshot; detach does not. The returned pointer
/// borrows the CString that the caller keeps alive for the FFI call.
fn snapshot_pointer(fd: jint, snapshot: Option<&CString>) -> Result<*const c_char, String> {
    if fd > 0 && snapshot.is_none() {
        return Err("VPN snapshot is required when attaching a TUN fd".to_owned());
    }
    Ok(snapshot.map_or(ptr::null(), |snapshot| snapshot.as_ptr()))
}

/// Take ownership of a string returned by easytier-ffi.
///
/// The pointer is always released for non-null input. A null pointer is an
/// FFI error, not an empty configuration.
unsafe fn take_ffi_string(value: *const c_char) -> Result<String, String> {
    if value.is_null() {
        return Err("FFI returned a null string".to_owned());
    }
    let result = unsafe { CStr::from_ptr(value) }
        .to_str()
        .map(str::to_owned)
        .map_err(|error| format!("FFI returned invalid UTF-8: {error}"));
    free_string(value);
    result
}

pub(crate) fn set_tun_fd_jni(
    mut env: JNIEnv,
    _class: JClass,
    inst_name: JString,
    fd: jint,
    snapshot_id: JString,
) -> jint {
    if inst_name.is_null() {
        throw_exception(&mut env, "instanceName is null");
        return -1;
    }
    let inst_name_cstr = match jstring_to_cstring(&mut env, &inst_name) {
        Ok(cstr) => cstr,
        Err(e) => {
            throw_exception(&mut env, &format!("Invalid instance name: {}", e));
            return -1;
        }
    };
    // Kotlin declares snapshotId nullable for the detach path. A positive FD
    // still requires it; C receives null only when detaching.
    let snapshot = match optional_jstring_to_cstring(&mut env, &snapshot_id) {
        Ok(value) => value,
        Err(error) => {
            throw_exception(&mut env, &format!("Invalid VPN snapshot: {error}"));
            return -1;
        }
    };
    let snapshot_ptr = match snapshot_pointer(fd, snapshot.as_ref()) {
        Ok(value) => value,
        Err(error) => {
            throw_exception(&mut env, &error);
            return -1;
        }
    };
    unsafe {
        let result = set_tun_fd(inst_name_cstr.as_ptr(), fd, snapshot_ptr);
        if result != 0 {
            let error = get_last_error().unwrap_or_else(|| "setTunFd failed".to_owned());
            throw_exception(&mut env, &error);
        }
        result
    }
}

pub(crate) fn get_mobile_tun_config_jni(
    mut env: JNIEnv,
    _class: JClass,
    inst_name: JString,
) -> jstring {
    if inst_name.is_null() {
        throw_exception(&mut env, "instanceName is null");
        return ptr::null_mut();
    }
    let name = match jstring_to_cstring(&mut env, &inst_name) {
        Ok(value) => value,
        Err(error) => {
            throw_exception(&mut env, &format!("Invalid instance name: {error}"));
            return ptr::null_mut();
        }
    };
    let config = unsafe { get_mobile_tun_config(name.as_ptr()) };
    if config.is_null() {
        throw_exception(
            &mut env,
            &get_last_error().unwrap_or_else(|| "VPN configuration is unavailable".to_owned()),
        );
        return ptr::null_mut();
    }
    // The FFI payload is already the Controller's complete JSON table. JNI
    // copies it without parsing or filtering routes.
    let json = match unsafe { take_ffi_string(config) } {
        Ok(json) => json,
        Err(error) => {
            throw_exception(&mut env, &format!("Invalid VPN configuration: {error}"));
            return ptr::null_mut();
        }
    };
    match env.new_string(json) {
        Ok(value) => value.into_raw(),
        Err(error) => {
            throw_exception(&mut env, &error.to_string());
            ptr::null_mut()
        }
    }
}

pub(crate) fn parse_config_jni(mut env: JNIEnv, _class: JClass, config: JString) -> jint {
    let config_cstr = match jstring_to_cstring(&mut env, &config) {
        Ok(cstr) => cstr,
        Err(e) => {
            throw_exception(&mut env, &format!("Invalid config string: {}", e));
            return -1;
        }
    };
    unsafe {
        let result = parse_config(config_cstr.as_ptr());
        if result != 0
            && let Some(error) = get_last_error()
        {
            throw_exception(&mut env, &error);
        }
        result
    }
}

pub(crate) fn run_network_instance_jni(mut env: JNIEnv, _class: JClass, config: JString) -> jint {
    let config_cstr = match jstring_to_cstring(&mut env, &config) {
        Ok(cstr) => cstr,
        Err(e) => {
            throw_exception(&mut env, &format!("Invalid config string: {}", e));
            return -1;
        }
    };
    unsafe {
        let result = run_network_instance(config_cstr.as_ptr());
        if result != 0
            && let Some(error) = get_last_error()
        {
            throw_exception(&mut env, &error);
        }
        result
    }
}

pub(crate) fn delete_network_instance_jni(
    mut env: JNIEnv,
    _class: JClass,
    instance_name: JString,
) -> jint {
    let instance_name = match jstring_to_cstring(&mut env, &instance_name) {
        Ok(name) => name,
        Err(error) => {
            throw_exception(&mut env, &format!("Invalid instance name: {error}"));
            return -1;
        }
    };
    let instance_names = [instance_name.as_ptr()];
    unsafe {
        let result = delete_network_instance(instance_names.as_ptr(), instance_names.len());
        if result != 0
            && let Some(error) = get_last_error()
        {
            throw_exception(&mut env, &error);
        }
        result
    }
}

pub(crate) fn retain_network_instance_jni(
    mut env: JNIEnv,
    _class: JClass,
    instance_names: JObjectArray,
) -> jint {
    if instance_names.is_null() {
        return retain_all(&mut env);
    }

    let array_length = match env.get_array_length(&instance_names) {
        Ok(len) => len as usize,
        Err(e) => {
            throw_exception(&mut env, &format!("Failed to get array length: {:?}", e));
            return -1;
        }
    };

    if array_length == 0 {
        return retain_all(&mut env);
    }

    let mut c_strings = Vec::with_capacity(array_length);
    let mut c_string_ptrs = Vec::with_capacity(array_length);

    for i in 0..array_length {
        let java_string = match env.get_object_array_element(&instance_names, i as i32) {
            Ok(obj) => obj,
            Err(e) => {
                throw_exception(
                    &mut env,
                    &format!("Failed to get array element {}: {:?}", i, e),
                );
                return -1;
            }
        };

        if java_string.is_null() {
            throw_exception(
                &mut env,
                &format!("Invalid instance name at index {}: null", i),
            );
            return -1;
        }

        let jstring = JString::from(java_string);
        let c_string = match jstring_to_cstring(&mut env, &jstring) {
            Ok(cstr) => cstr,
            Err(e) => {
                throw_exception(
                    &mut env,
                    &format!("Invalid instance name at index {}: {}", i, e),
                );
                return -1;
            }
        };

        c_string_ptrs.push(c_string.as_ptr());
        c_strings.push(c_string);
    }

    unsafe {
        let result = retain_network_instance(c_string_ptrs.as_ptr(), c_string_ptrs.len());
        if result != 0
            && let Some(error) = get_last_error()
        {
            throw_exception(&mut env, &error);
        }
        result
    }
}

fn retain_all(env: &mut JNIEnv) -> jint {
    unsafe {
        let result = retain_network_instance(ptr::null(), 0);
        if result != 0
            && let Some(error) = get_last_error()
        {
            throw_exception(env, &error);
        }
        result
    }
}

pub(crate) fn collect_network_infos_jni(
    mut env: JNIEnv,
    _class: JClass,
    max_length: jint,
) -> jstring {
    let max_length = max_length.max(0) as usize;
    let mut infos = vec![
        KeyValuePair {
            key: ptr::null(),
            value: ptr::null(),
        };
        max_length
    ];

    unsafe {
        let count = collect_network_infos(infos.as_mut_ptr(), max_length);
        if count < 0 {
            if let Some(error) = get_last_error() {
                throw_exception(&mut env, &error);
            }
            return ptr::null_mut();
        }

        let mut ret = NetworkInstanceRunningInfoMap::default();
        for info in infos.iter().take(count as usize) {
            let key_ptr = info.key;
            let val_ptr = info.value;
            if key_ptr.is_null() || val_ptr.is_null() {
                break;
            }

            let key = CStr::from_ptr(key_ptr).to_string_lossy().into_owned();
            let val = CStr::from_ptr(val_ptr).to_string_lossy().into_owned();
            free_string(key_ptr);
            free_string(val_ptr);
            let value = match serde_json::from_str::<NetworkInstanceRunningInfo>(&val) {
                Ok(v) => v,
                Err(_) => {
                    throw_exception(&mut env, "Failed to parse JSON");
                    continue;
                }
            };
            ret.map.insert(key, value);
        }

        let json_str = serde_json::to_string(&ret).unwrap_or_else(|_| "{}".to_string());
        match env.new_string(&json_str) {
            Ok(jstr) => jstr.into_raw(),
            Err(_) => {
                throw_exception(&mut env, "Failed to create JSON string");
                ptr::null_mut()
            }
        }
    }
}

pub(crate) fn list_instances_jni(mut env: JNIEnv, _class: JClass, max_length: jint) -> jstring {
    let max_length = max_length.max(0) as usize;
    let mut infos = vec![
        KeyValuePair {
            key: ptr::null(),
            value: ptr::null(),
        };
        max_length
    ];

    unsafe {
        let count = list_instance(infos.as_mut_ptr(), max_length);
        if count < 0 {
            if let Some(error) = get_last_error() {
                throw_exception(&mut env, &error);
            }
            return ptr::null_mut();
        }

        let mut ret = serde_json::Map::new();
        for info in infos.iter().take(count as usize) {
            let key_ptr = info.key;
            let val_ptr = info.value;
            if key_ptr.is_null() || val_ptr.is_null() {
                break;
            }

            let key = CStr::from_ptr(key_ptr).to_string_lossy().into_owned();
            let val = CStr::from_ptr(val_ptr).to_string_lossy().into_owned();
            free_string(key_ptr);
            free_string(val_ptr);
            ret.insert(key, serde_json::Value::String(val));
        }

        let json_str = serde_json::Value::Object(ret).to_string();
        match env.new_string(&json_str) {
            Ok(jstr) => jstr.into_raw(),
            Err(_) => {
                throw_exception(&mut env, "Failed to create instance list JSON string");
                ptr::null_mut()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_fd_requires_a_snapshot_and_detach_does_not() {
        let snapshot = CString::new("00000000-0000-0000-0000-000000000001").unwrap();

        assert!(snapshot_pointer(1, None).is_err());
        assert_eq!(
            snapshot_pointer(1, Some(&snapshot)).unwrap(),
            snapshot.as_ptr()
        );
        assert!(snapshot_pointer(0, None).unwrap().is_null());
        assert!(snapshot_pointer(-1, None).unwrap().is_null());
        assert_eq!(
            snapshot_pointer(0, Some(&snapshot)).unwrap(),
            snapshot.as_ptr()
        );
    }

    #[test]
    fn ffi_string_conversion_rejects_null_and_invalid_utf8() {
        assert!(
            unsafe { take_ffi_string(ptr::null()) }
                .unwrap_err()
                .contains("null")
        );

        let valid = CString::new("{\"routes\":[]}").unwrap().into_raw();
        assert_eq!(
            unsafe { take_ffi_string(valid) }.unwrap(),
            "{\"routes\":[]}"
        );

        let invalid = CString::new(vec![0xff, b'A']).unwrap().into_raw();
        assert!(
            unsafe { take_ffi_string(invalid) }
                .unwrap_err()
                .contains("invalid UTF-8")
        );
    }
}
