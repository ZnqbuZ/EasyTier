//! Native ownership and continuous driving of an instance's Tokio runtime.

use guarden::guarded;
use std::sync::mpsc;
use tokio::{
    runtime::{Builder, Handle},
    sync::oneshot,
};

#[derive(Debug)]
pub(crate) struct NativeExecutor {
    handle: Handle,
    // Dropping the owner stops the driver, including on construction failure.
    _shutdown: oneshot::Sender<()>,
}

impl NativeExecutor {
    pub(crate) fn new(multi_thread: bool, thread_count: u32) -> anyhow::Result<Self> {
        Self::named("easytier-instance", multi_thread, thread_count)
    }

    fn named(name: &str, multi_thread: bool, thread_count: u32) -> anyhow::Result<Self> {
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let name = name.to_owned();
        std::thread::Builder::new()
            .name(name.clone())
            .spawn(move || {
                let mut builder = if multi_thread {
                    let mut builder = Builder::new_multi_thread();
                    builder.worker_threads(2.max(thread_count as usize));
                    builder
                } else {
                    Builder::new_current_thread()
                };
                let runtime = match builder.thread_name(name).enable_all().build() {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                // Release the runtime without blocking its workers, including on unwind.
                guarded!([runtime] runtime.shutdown_background());
                if ready_tx.send(Ok(runtime.handle().clone())).is_ok() {
                    runtime.block_on(async {
                        let _ = shutdown_rx.await;
                    });
                }
            })?;
        let handle = ready_rx.recv()??;
        Ok(Self {
            handle,
            _shutdown: shutdown_tx,
        })
    }

    pub(crate) fn handle(&self) -> Handle {
        self.handle.clone()
    }
}

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
            let executor = NativeExecutor::new(multi_thread, count).unwrap();
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
            let executor = NativeExecutor::new(multi_thread, 2).unwrap();
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
