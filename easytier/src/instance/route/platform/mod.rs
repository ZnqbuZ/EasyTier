use super::{OsRoute, RouteBackend, RouteError};

cfg_select! {
    target_os = "linux" => {
        mod linux;
        pub(crate) use linux::PlatformRouteBackend;
    },
    windows => {
        mod windows;
        pub(crate) use windows::PlatformRouteBackend;
    },
    any(target_os = "macos", target_os = "freebsd") => {
        mod bsd;
        pub(crate) use bsd::PlatformRouteBackend;
    },
    _ => {
        mod unsupported;
        pub(crate) use unsupported::PlatformRouteBackend;
    },
}

const _: () = {
    const fn _assert()
    where
        PlatformRouteBackend: RouteBackend + Send + Sync,
    {
    }
};
