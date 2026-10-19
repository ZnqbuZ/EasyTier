//! Instance-specific name for the native executor owner.

pub(super) use crate::common::native_executor::NativeExecutor as NativeInstanceExecutor;
#[cfg(test)]
mod tests {
    use std::{future::pending, time::Duration};

    use tokio::runtime::RuntimeFlavor;

    use super::*;

    #[tokio::test]
    async fn honors_runtime_flavor_and_worker_count() {
        for (multi_thread, count, expected_workers) in [
            (false, 8, 1),
            (true, 0, 2),
            (true, 1, 2),
            (true, 2, 2),
            (true, 4, 4),
        ] {
            let executor = NativeInstanceExecutor::new(multi_thread, count).unwrap();
            let handle = executor.handle();
            assert_eq!(handle.metrics().num_workers(), expected_workers);
            assert_eq!(
                handle.runtime_flavor(),
                if multi_thread {
                    RuntimeFlavor::MultiThread
                } else {
                    RuntimeFlavor::CurrentThread
                }
            );
            let caller_thread = std::thread::current().id();
            let task_thread = handle
                .spawn(async { std::thread::current().id() })
                .await
                .unwrap();
            assert_ne!(task_thread, caller_thread);
        }
    }

    #[tokio::test]
    async fn dropping_owner_from_a_worker_shuts_down_tasks() {
        for multi_thread in [false, true] {
            let executor = NativeInstanceExecutor::new(multi_thread, 2).unwrap();
            let handle = executor.handle();
            let task = handle.spawn(pending::<()>());
            handle.spawn(async move { drop(executor) });
            let error = tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .expect("runtime must shut down without joining its own worker")
                .unwrap_err();
            assert!(error.is_cancelled());
        }
    }
}