use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for var in [
        "CARGO_CFG_TARGET_OS",
        "CARGO_CFG_TARGET_ENV",
        "CARGO_FEATURE_MACOS_NE",
    ] {
        println!("cargo:rerun-if-env-changed={var}");
    }

    println!("cargo:rustc-check-cfg=cfg(mobile)");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let macos_ne = env::var_os("CARGO_FEATURE_MACOS_NE").is_some();

    // Keep this identical to the `mobile` alias in `easytier/build/main.rs`:
    // Core and Native must trim the same fields and actions together.
    let mobile = matches!(target_os.as_str(), "android" | "ios")
        || (target_os == "macos" && macos_ne)
        || target_env == "ohos";

    if mobile {
        println!("cargo:rustc-cfg=mobile");
    }
}
