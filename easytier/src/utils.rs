use anyhow::Context;
use dashmap::DashMap;
use futures::{Sink, Stream};
use once_cell::sync::Lazy;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::{fs::OpenOptions, str::FromStr};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
    layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer, Registry,
};

use crate::common::{
    config::LoggingConfigLoader, get_logger_timer_rfc3339, tracing_rolling_appender::*,
};

pub type PeerRoutePair = crate::proto::api::instance::PeerRoutePair;

pub fn cost_to_str(cost: i32) -> String {
    if cost == 1 {
        "p2p".to_string()
    } else {
        format!("relay({})", cost)
    }
}

pub fn float_to_str(f: f64, precision: usize) -> String {
    format!("{:.1$}", f, precision)
}

pub type NewFilterSender = std::sync::mpsc::Sender<String>;

pub fn init_logger(
    config: impl LoggingConfigLoader,
    need_reload: bool,
) -> Result<Option<NewFilterSender>, anyhow::Error> {
    use crate::rpc_service::logger::{CURRENT_LOG_LEVEL, LOGGER_LEVEL_SENDER};

    let file_config = config.get_file_logger_config();
    let file_level = file_config
        .level
        .map(|s| s.parse().unwrap())
        .unwrap_or(LevelFilter::OFF);

    let mut ret_sender: Option<NewFilterSender> = None;

    // logger to rolling file
    let mut file_layer = None;
    if file_level != LevelFilter::OFF || need_reload {
        let mut l = tracing_subscriber::fmt::layer();
        l.set_ansi(false);
        let file_filter = EnvFilter::builder()
            .with_default_directive(file_level.into())
            .from_env()
            .with_context(|| "failed to create file filter")?;
        let (file_filter, file_filter_reloader) =
            tracing_subscriber::reload::Layer::new(file_filter);

        if need_reload {
            let (sender, recver) = std::sync::mpsc::channel();
            ret_sender = Some(sender.clone());

            // 初始化全局状态
            let _ = LOGGER_LEVEL_SENDER.set(std::sync::Mutex::new(sender));
            let _ = CURRENT_LOG_LEVEL.set(std::sync::Mutex::new(file_level.to_string()));

            std::thread::spawn(move || {
                while let Ok(lf) = recver.recv() {
                    let e = file_filter_reloader.modify(|f| {
                        if let Ok(nf) = EnvFilter::builder()
                            .with_default_directive(lf.parse::<LevelFilter>().unwrap().into())
                            .from_env()
                            .with_context(|| "failed to create file filter")
                        {
                            println!("Reload log filter succeed, new filter level: {:?}", lf);
                            *f = nf;
                        }
                    });
                    if e.is_err() {
                        println!("Failed to reload log filter: {:?}", e);
                    }
                }
                println!("Stop log filter reloader");
            });
        }

        let dir = file_config.dir.as_deref().unwrap_or(".");
        let file = file_config.file.as_deref().unwrap_or("easytier.log");
        let path = std::path::Path::new(dir).join(file);
        let path_str = path.to_string_lossy().into_owned();

        let builder = RollingFileAppenderBase::builder();
        let file_appender = builder
            .filename(path_str)
            .condition_daily()
            .max_filecount(file_config.count.unwrap_or(10))
            .condition_max_file_size(file_config.size_mb.unwrap_or(100) * 1024 * 1024)
            .build()
            .unwrap();

        let wrapper = FileAppenderWrapper::new(file_appender);

        // Create a simple wrapper that implements MakeWriter
        file_layer = Some(
            l.with_writer(wrapper)
                .with_timer(get_logger_timer_rfc3339())
                .with_filter(file_filter),
        );
    }

    // logger to console
    let console_config = config.get_console_logger_config();
    let console_level = console_config
        .level
        .map(|s| s.parse().unwrap())
        .unwrap_or(LevelFilter::OFF);

    let console_filter = EnvFilter::builder()
        .with_default_directive(console_level.into())
        .from_env()?;

    let console_layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_timer(get_logger_timer_rfc3339())
        .with_writer(std::io::stderr)
        .with_filter(console_filter);

    let registry = Registry::default();

    #[cfg(not(feature = "tracing"))]
    {
        registry.with(console_layer).with(file_layer).init();
    }

    #[cfg(feature = "tracing")]
    {
        let console_subscriber_layer = console_subscriber::ConsoleLayer::builder().spawn();
        registry
            .with(console_layer)
            .with(file_layer)
            .with(console_subscriber_layer)
            .init();
    }

    Ok(ret_sender)
}

#[cfg(target_os = "windows")]
pub fn utf8_or_gbk_to_string(s: &[u8]) -> String {
    use encoding::{all::GBK, DecoderTrap, Encoding};
    if let Ok(utf8_str) = String::from_utf8(s.to_vec()) {
        utf8_str
    } else {
        // 如果解码失败，则尝试使用GBK解码
        if let Ok(gbk_str) = GBK.decode(s, DecoderTrap::Strict) {
            gbk_str
        } else {
            String::from_utf8_lossy(s).to_string()
        }
    }
}

thread_local! {
    static PANIC_COUNT : std::cell::RefCell<u32> = const { std::cell::RefCell::new(0) };
}

pub fn setup_panic_handler() {
    use std::backtrace;
    use std::io::Write;
    std::panic::set_hook(Box::new(|info| {
        PANIC_COUNT.with(|c| {
            let mut count = c.borrow_mut();
            *count += 1;
        });
        let panic_count = PANIC_COUNT.with(|c| *c.borrow());
        if panic_count > 1 {
            println!("panic happened more than once, exit immediately");
            std::process::exit(1);
        }

        let payload = info.payload();
        let payload_str: Option<&str> = if let Some(s) = payload.downcast_ref::<&str>() {
            Some(s)
        } else if let Some(s) = payload.downcast_ref::<String>() {
            Some(s)
        } else {
            None
        };
        let payload_str = payload_str.unwrap_or("<unknown panic info>");
        // The current implementation always returns `Some`.
        let location = info.location().unwrap();
        let thread = std::thread::current();
        let thread = thread.name().unwrap_or("<unnamed>");

        let tmp_path = std::env::temp_dir().join("easytier-panic.log");
        let candidate_path = [
            std::path::PathBuf::from_str("easytier-panic.log").ok(),
            Some(tmp_path),
        ];
        let mut file = None;
        let mut file_path = None;
        for path in candidate_path.iter().filter_map(|p| p.clone()) {
            file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path.clone())
                .ok();
            if file.is_some() {
                file_path = Some(path);
                break;
            }
        }

        println!("{}", rust_i18n::t!("core_app.panic_backtrace_save"));

        // write str to stderr & file
        let write_err = |s: String| {
            let mut stderr = std::io::stderr();
            let content = format!("{}: {}", chrono::Local::now(), s);
            let _ = writeln!(stderr, "{}", content);
            if let Some(mut f) = file.as_ref() {
                let _ = writeln!(f, "{}", content);
            }
        };

        write_err("panic occurred, if this is a bug, please report this issue on github (https://github.com/easytier/easytier/issues)".to_string());
        write_err(format!("easytier version: {}", crate::VERSION));
        write_err(format!("os version: {}", std::env::consts::OS));
        write_err(format!("arch: {}", std::env::consts::ARCH));
        write_err(format!(
            "panic is recorded in: {}",
            file_path
                .and_then(|p| p.to_str().map(|x| x.to_string()))
                .unwrap_or("<no file>".to_string())
        ));
        write_err(format!("thread: {}", thread));
        write_err(format!("time: {}", chrono::Local::now()));
        write_err(format!("location: {}", location));
        write_err(format!("panic info: {}", payload_str));

        // backtrace is risky, so use it last
        let backtrace = backtrace::Backtrace::force_capture();
        write_err(format!("backtrace: {:#?}", backtrace));

        std::process::exit(1);
    }));
}

pub fn check_tcp_available(port: u16) -> bool {
    use std::net::TcpListener;
    let s = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port);
    TcpListener::bind(s).is_ok()
}

pub fn find_free_tcp_port(mut range: std::ops::Range<u16>) -> Option<u16> {
    range.find(|&port| check_tcp_available(port))
}

pub fn weak_upgrade<T>(weak: &std::sync::Weak<T>) -> anyhow::Result<std::sync::Arc<T>> {
    weak.upgrade()
        .ok_or_else(|| anyhow::anyhow!("{} not available", std::any::type_name::<T>()))
}

static NEXT_STREAM_ID: AtomicUsize = AtomicUsize::new(0);
pub static STREAM_MONITOR: Lazy<DashMap<usize, Arc<Stats>>> = Lazy::new(|| DashMap::new());

pub fn run_stream_monitor() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
        loop {
            interval.tick().await;

            if STREAM_MONITOR.is_empty() {
                continue;
            }

            println!("--- 实时速率监控 (活跃流: {}) ---", STREAM_MONITOR.len());

            let mut snapshot = Vec::new();

            for item in STREAM_MONITOR.iter() {
                let stats = item.value();
                let curr_read = stats.total_read.load(Ordering::Relaxed);
                let curr_write = stats.total_write.load(Ordering::Relaxed);
                let curr_read_pending = stats.total_read_pending.load(Ordering::Relaxed);
                let curr_write_pending = stats.total_write_pending.load(Ordering::Relaxed);

                let prev_read = stats.last_read.swap(curr_read, Ordering::Relaxed);
                let prev_write = stats.last_write.swap(curr_write, Ordering::Relaxed);
                let prev_read_pending = stats
                    .last_read_pending
                    .swap(curr_read_pending, Ordering::Relaxed);
                let prev_write_pending = stats
                    .last_write_pending
                    .swap(curr_write_pending, Ordering::Relaxed);

                let rate_read = curr_read.saturating_sub(prev_read);
                let rate_write = curr_write.saturating_sub(prev_write);
                let delta_read_pending = curr_read_pending.saturating_sub(prev_read_pending);
                let delta_write_pending = curr_write_pending.saturating_sub(prev_write_pending);

                snapshot.push((
                    stats.id,
                    stats.name.clone(),
                    stats.content,
                    rate_read,
                    rate_write,
                    delta_read_pending,
                    delta_write_pending,
                    curr_read,
                    curr_write,
                    stats.total_read_error.load(Ordering::Relaxed),
                    stats.total_write_error.load(Ordering::Relaxed),
                ));
            }

            snapshot.sort_by_key(|k| k.0);

            let to_mb = |bytes: u64| -> String {
                let bits = bytes as f64 * 8.0;
                let mb = bits / 1_000_000.0; // 网络常用 1000 进制，如果习惯系统进制可用 1024.0 * 1024.0
                if mb < 0.01 && bytes > 0 {
                    format!("{:.4}", mb) // 极小流量保留更多小数
                } else {
                    format!("{:.2}", mb) // 正常保留两位小数
                }
            };

            for (_, name, content, r, w, r_pending, w_pending, r_total, w_total, r_error, w_error) in snapshot
            {
                match content {
                    Content::Byte => {
                        println!(
                            "[{}]: Rate (R: {} Mbps, W: {} Mbps) | Blocked (R: {} s^-1, W: {} s^-1) | Total (R: {} Mb, W: {} Mb) | Error (R: {}, W: {})",
                            name,
                            to_mb(r),
                            to_mb(w),
                            r_pending,
                            w_pending,
                            to_mb(r_total),
                            to_mb(w_total),
                            r_error,
                            w_error,
                        );
                    }
                    Content::Item => {
                        println!(
                            "[{}]: Rate (R: {} s^-1, W: {} s^-1) | Blocked (R: {} s^-1, W: {} s^-1) | Total (R: {}, W: {}) | Error (R: {}, W: {})",
                            name,
                            r,
                            w,
                            r_pending,
                            w_pending,
                            r_total,
                            w_total,
                            r_error,
                            w_error,
                        );
                    }
                }
            }
            println!("--------------------------------");
        }
    });
}

#[derive(Debug, Clone, Copy, Default)]
pub enum Content {
    #[default]
    Byte,
    Item,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub id: usize,
    pub name: String, // 标识：如 "192.168.1.5 <-> 8.8.8.8"
    pub content: Content,
    pub total_read: AtomicU64,  // 总接收字节
    pub total_write: AtomicU64, // 总发送字节
    pub last_read: AtomicU64,   // 上一次采样的接收字节（用于算速率）
    pub last_write: AtomicU64,  // 上一次采样的发送字节
    pub total_read_pending: AtomicUsize,
    pub last_read_pending: AtomicUsize,
    pub total_write_pending: AtomicUsize, // 总共遇到了多少次写阻塞
    pub last_write_pending: AtomicUsize,  // 上一次采样的阻塞次数（用于计算增量）
    pub total_read_error: AtomicUsize,
    pub total_write_error: AtomicUsize,
}

pub struct Monitored<T> {
    inner: T,
    stats: Arc<Stats>,
}

impl<T> Monitored<T> {
    pub fn new(inner: T, name: &str, content: Content) -> Self {
        let id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
        let stats = Arc::new(Stats {
            id,
            name: name.to_string(),
            content,
            ..Default::default()
        });
        STREAM_MONITOR.insert(id, stats.clone());
        Self { inner, stats }
    }
}

impl<T> Drop for Monitored<T> {
    fn drop(&mut self) {
        info!("Stream dropped, stats: {:?}", self.stats);
        STREAM_MONITOR.remove(&self.stats.id);
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Monitored<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        match poll {
            Poll::Ready(Ok(())) => {
                let n = (buf.filled().len() - before) as u64;
                self.stats.total_read.fetch_add(n, Ordering::Relaxed);
            }
            Poll::Ready(Err(_)) => {
                self.stats.total_read_error.fetch_add(1, Ordering::Relaxed);
            }
            Poll::Pending => {
                self.stats
                    .total_read_pending
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Monitored<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        match poll {
            Poll::Ready(Ok(n)) => {
                self.stats
                    .total_write
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
            Poll::Ready(Err(_)) => {
                self.stats.total_write_error.fetch_add(1, Ordering::Relaxed);
            }
            Poll::Pending => {
                self.stats
                    .total_write_pending
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        poll
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<T: Stream + Unpin> Stream for Monitored<T> {
    type Item = T::Item;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let poll = Pin::new(&mut self.inner).poll_next(cx);

        match &poll {
            Poll::Ready(Some(_)) => {
                // 成功接收到一个消息 (Item)
                self.stats.total_read.fetch_add(1, Ordering::Relaxed);
                // 可以在这里更新 last_rx 时间戳
            }
            Poll::Ready(None) => {
                // 流结束了 (EOF)，不做特殊统计
            }
            Poll::Pending => {
                self.stats
                    .total_read_pending
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        poll
    }
}

impl<T, Item> Sink<Item> for Monitored<T>
where
    T: Sink<Item> + Unpin,
{
    type Error = T::Error;

    // 1. 检查底层是否准备好发送
    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let poll = Pin::new(&mut self.inner).poll_ready(cx);
        if poll.is_pending() {
            // 只有当 Sink 还没准备好接收数据时（背压），才算 Write Pending
            self.stats
                .total_write_pending
                .fetch_add(1, Ordering::Relaxed);
        }
        poll
    }

    // 2. 开始发送消息
    fn start_send(mut self: Pin<&mut Self>, item: Item) -> Result<(), Self::Error> {
        // 调用底层发送
        let res = Pin::new(&mut self.inner).start_send(item);
        match res {
            Ok(_) => {
                self.stats.total_write.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.stats.total_write_error.fetch_add(1, Ordering::Relaxed);
            }
        }
        res
    }

    // 3. 刷新缓冲区
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let poll = Pin::new(&mut self.inner).poll_flush(cx);
        if poll.is_pending() {
            // Flush 等待也算 Write Pending
            self.stats
                .total_write_pending
                .fetch_add(1, Ordering::Relaxed);
        }
        poll
    }

    // 4. 关闭流
    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use crate::common::config::{self};

    use super::*;

    async fn test_logger_reload() {
        println!("current working dir: {:?}", std::env::current_dir());
        let config = config::LoggingConfigBuilder::default().build().unwrap();
        let s = init_logger(&config, true).unwrap();
        tracing::debug!("test not display debug");
        s.unwrap().send(LevelFilter::DEBUG.to_string()).unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        tracing::debug!("test display debug");
    }
}
