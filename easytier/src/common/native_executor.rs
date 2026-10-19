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


