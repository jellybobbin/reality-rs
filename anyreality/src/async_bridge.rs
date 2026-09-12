//! Bridge between blocking REALITY `StreamOwned` and async tokio streams.
//!
//! Our forked rustls cannot use `tokio-rustls`, so the REALITY TLS layer
//! is driven through `rustls_util::StreamOwned` on a `std::net::TcpStream`.
//! This module wraps that blocking object behind a `tokio::io::DuplexStream`
//! so it can be plugged into anytls (which expects `AsyncRead + AsyncWrite`).
//!
//! A dedicated OS worker thread pumps bytes between the TLS stream and the
//! "remote" half of an in-process tokio duplex pipe, using the same
//! non-blocking polling pattern already used for the SOCKS relay loop.

use core::time::Duration;
use std::io::{Read, Write};

use anyhow::Result;
use rustls::Connection;
use rustls_util::StreamOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::runtime::Handle;

const PUMP_BUFFER: usize = 64 * 1024;
const RELAY_HIGH_WATER: usize = 256 * 1024;

/// Convert a fully handshaken blocking REALITY TLS stream into an
/// async duplex usable as `Box<dyn AsyncReadWrite>`.
///
/// Must be called from inside a tokio runtime; the captured runtime
/// handle is used by the worker thread to drive the async side.
pub fn into_async<C>(tls: StreamOwned<C, std::net::TcpStream>) -> std::io::Result<DuplexStream>
where
    C: Connection + Send + 'static,
{
    let (local, remote) = tokio::io::duplex(PUMP_BUFFER);
    let handle = Handle::current();
    std::thread::spawn(move || {
        if let Err(error) = pump(handle, tls, remote) {
            log::trace!("REALITY async bridge pump exited: {error:#}");
        }
    });
    Ok(local)
}

#[allow(clippy::std_instead_of_core)]
fn pump<C>(
    handle: Handle,
    mut tls: StreamOwned<C, std::net::TcpStream>,
    duplex: DuplexStream,
) -> Result<()>
where
    C: Connection + Send + 'static,
{
    tls.sock.set_nonblocking(true)?;
    let tls_eof = pump_io(&handle, &mut tls, duplex)?;
    if !tls_eof {
        tls.conn.send_close_notify();
        let _ = tls.flush();
    }
    let _ = tls
        .sock
        .shutdown(std::net::Shutdown::Both);
    Ok(())
}

fn pump_io<T: Read + Write>(handle: &Handle, tls: &mut T, duplex: DuplexStream) -> Result<bool> {
    let (mut duplex_read, mut duplex_write) = tokio::io::split(duplex);

    let mut tls_to_app: Vec<u8> = Vec::with_capacity(PUMP_BUFFER);
    let mut app_to_tls: Vec<u8> = Vec::with_capacity(PUMP_BUFFER);
    let mut buf = vec![0u8; PUMP_BUFFER];
    let mut tls_eof = false;
    let mut app_eof = false;

    loop {
        let mut progressed = false;

        // TLS -> app (async duplex write)
        if !tls_eof && tls_to_app.len() < RELAY_HIGH_WATER {
            match tls.read(&mut buf) {
                Ok(0) => {
                    tls_eof = true;
                    progressed = true;
                }
                Ok(read) => {
                    tls_to_app.extend_from_slice(&buf[..read]);
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    log::trace!("bridge: tls read error: {error}");
                    tls_eof = true;
                }
            }
        }

        if !tls_to_app.is_empty() {
            let written = handle.block_on(async {
                tokio::time::timeout(Duration::from_millis(2), duplex_write.write(&tls_to_app))
                    .await
            });
            match written {
                Ok(Ok(0)) => app_eof = true,
                Ok(Ok(n)) => {
                    tls_to_app.drain(..n);
                    progressed = true;
                }
                Ok(Err(error)) => {
                    log::trace!("bridge: duplex write error: {error}");
                    app_eof = true;
                }
                Err(_) => {}
            }
        }

        // app -> TLS (async duplex read)
        if !app_eof && app_to_tls.len() < RELAY_HIGH_WATER {
            // Use a short timeout so we don't starve the TLS side.
            let res = handle.block_on(async {
                tokio::time::timeout(Duration::from_millis(2), duplex_read.read(&mut buf)).await
            });
            match res {
                Ok(Ok(0)) => {
                    app_eof = true;
                    progressed = true;
                }
                Ok(Ok(n)) => {
                    app_to_tls.extend_from_slice(&buf[..n]);
                    progressed = true;
                }
                Ok(Err(error)) => {
                    log::trace!("bridge: duplex read error: {error}");
                    app_eof = true;
                }
                Err(_) => {
                    // timeout — no app data right now
                }
            }
        }

        if !app_to_tls.is_empty() {
            match tls.write(&app_to_tls) {
                Ok(0) => tls_eof = true,
                Ok(n) => {
                    app_to_tls.drain(..n);
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => {
                    log::trace!("bridge: tls write error: {error}");
                    tls_eof = true;
                }
            }
        }
        match tls.flush() {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }

        if app_eof && app_to_tls.is_empty() {
            break;
        }

        if tls_eof && tls_to_app.is_empty() && app_to_tls.is_empty() {
            break;
        }

        if !progressed {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    Ok(tls_eof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    struct TestTransport {
        remaining: usize,
        written: mpsc::Sender<Vec<u8>>,
    }

    impl Read for TestTransport {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            let count = buffer.len().min(self.remaining);
            buffer[..count].fill(42);
            self.remaining -= count;
            Ok(count)
        }
    }

    impl Write for TestTransport {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.written
                .send(buffer.to_vec())
                .unwrap();
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_tls_flush_is_retried_without_new_app_data() {
        struct BufferedTransport {
            pending: Vec<u8>,
            blocked_once: bool,
            flushed: mpsc::Sender<Vec<u8>>,
        }

        impl Read for BufferedTransport {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::WouldBlock.into())
            }
        }

        impl Write for BufferedTransport {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.pending.extend_from_slice(buffer);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                if !self.pending.is_empty() {
                    if !self.blocked_once {
                        self.blocked_once = true;
                        return Err(std::io::ErrorKind::WouldBlock.into());
                    }
                    self.flushed
                        .send(core::mem::take(&mut self.pending))
                        .unwrap();
                }
                Ok(())
            }
        }

        let (mut app, remote) = tokio::io::duplex(1024);
        let (flushed, received) = mpsc::channel();
        let handle = Handle::current();
        let worker = std::thread::spawn(move || {
            let mut transport = BufferedTransport {
                pending: Vec::new(),
                blocked_once: false,
                flushed,
            };
            pump_io(&handle, &mut transport, remote)
        });
        app.write_all(b"pending").await.unwrap();
        let result = received.recv_timeout(Duration::from_secs(1));
        drop(app);
        worker.join().unwrap().unwrap();
        assert_eq!(
            result.expect("pending TLS output must be retried without new app data"),
            b"pending"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_app_reader_does_not_block_outbound_data() {
        let (mut app, remote) = tokio::io::duplex(1024);
        let (written, received) = mpsc::channel();
        let handle = Handle::current();
        let worker = std::thread::spawn(move || {
            let mut transport = TestTransport {
                remaining: PUMP_BUFFER * 2,
                written,
            };
            pump_io(&handle, &mut transport, remote)
        });

        app.write_all(b"first").await.unwrap();
        assert_eq!(
            received
                .recv_timeout(Duration::from_secs(1))
                .unwrap(),
            b"first"
        );
        app.write_all(b"next").await.unwrap();
        let result = received.recv_timeout(Duration::from_secs(1));
        let mut buffer = vec![0u8; PUMP_BUFFER * 2];
        let read_result =
            tokio::time::timeout(Duration::from_secs(2), app.read_exact(&mut buffer)).await;
        drop(app);
        worker.join().unwrap().unwrap();
        assert_eq!(
            result.expect("outbound traffic must progress even while the app is not reading"),
            b"next"
        );
        read_result
            .expect("buffered inbound data must drain after reading resumes")
            .unwrap();
        assert!(buffer.iter().all(|byte| *byte == 42));
    }
}
