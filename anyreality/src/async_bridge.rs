//! Bridge between blocking REALITY `StreamOwned` and async tokio streams.
//!
//! Our forked rustls cannot use `tokio-rustls`, so the REALITY TLS layer is
//! driven through `rustls_util::StreamOwned` on a `std::net::TcpStream`. This
//! module wraps that blocking object behind an async [`BridgeStream`] so it can
//! be plugged into anytls (which expects `AsyncRead + AsyncWrite`).
//!
//! A single dedicated OS worker thread owns the TLS stream and shuttles bytes
//! between it and two channels. Crucially the thread **parks in the kernel** (a
//! blocking socket read with a short timeout) when idle instead of spinning:
//! the previous implementation busy-looped with `Handle::block_on` on every
//! carrier, which starved the async runtime once many carriers were live and
//! stalled every session's SYNACK and heartbeat traffic.

use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io::{self, Read, Write};

use rustls::Connection;
use rustls_util::StreamOwned;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

const PUMP_BUFFER: usize = 64 * 1024;
const RELAY_HIGH_WATER: usize = 256 * 1024;
/// Inbound (TLS -> app) chunk backlog before the bridge applies TCP
/// backpressure by pausing socket reads. Bounds per-carrier inbound memory.
const INBOUND_CHANNEL_CAP: usize = 16;
/// Blocking socket read/write timeout. Bounds how long the worker parks in the
/// kernel before it re-checks the outbound queue, i.e. the worst-case app->TLS
/// wakeup latency. Small enough to stay responsive, large enough to avoid a
/// busy loop.
const SOCKET_POLL: Duration = Duration::from_millis(5);
/// Poll interval used only while inbound delivery is backpressured (the app is
/// not reading), so outbound traffic keeps flowing without a tight spin.
const BACKPRESSURE_POLL: Duration = Duration::from_millis(1);

fn would_block(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Async view over the REALITY TLS carrier. Reads pull decrypted bytes produced
/// by the worker thread; writes hand plaintext to the worker thread.
pub struct BridgeStream {
    inbound: mpsc::Receiver<Vec<u8>>,
    leftover: Vec<u8>,
    leftover_pos: usize,
    outbound: Option<mpsc::UnboundedSender<Vec<u8>>>,
}

/// Convert a fully handshaken blocking REALITY TLS stream into an async stream
/// usable as `Box<dyn AsyncReadWrite>`.
pub fn into_async<C>(tls: StreamOwned<C, std::net::TcpStream>) -> io::Result<BridgeStream>
where
    C: Connection + Send + 'static,
{
    let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(INBOUND_CHANNEL_CAP);
    let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    std::thread::spawn(move || {
        if let Err(error) = pump(tls, inbound_tx, outbound_rx) {
            log::trace!("REALITY async bridge pump exited: {error:#}");
        }
    });
    Ok(BridgeStream {
        inbound: inbound_rx,
        leftover: Vec::new(),
        leftover_pos: 0,
        outbound: Some(outbound_tx),
    })
}

fn pump<C>(
    mut tls: StreamOwned<C, std::net::TcpStream>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    mut outbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) -> io::Result<()>
where
    C: Connection + Send + 'static,
{
    // Blocking socket with short read/write timeouts: the worker parks in the
    // kernel while idle instead of busy-polling, and a timeout simply surfaces
    // as WouldBlock (EAGAIN on Linux) which the loop treats as "no progress".
    tls.sock.set_nonblocking(false)?;
    tls.sock
        .set_read_timeout(Some(SOCKET_POLL))?;
    tls.sock
        .set_write_timeout(Some(SOCKET_POLL))?;

    let result = pump_io(&mut tls, &inbound_tx, &mut outbound_rx);

    tls.conn.send_close_notify();
    let _ = tls.flush();
    let _ = tls
        .sock
        .shutdown(std::net::Shutdown::Both);
    result
}

fn pump_io<T: Read + Write>(
    tls: &mut T,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
    outbound_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> io::Result<()> {
    let mut buf = vec![0u8; PUMP_BUFFER];
    let mut out_buf: Vec<u8> = Vec::new();
    let mut inbound_pending: Option<Vec<u8>> = None;
    let mut app_closed = false;

    loop {
        // 1) Collect queued app -> TLS bytes (bounded so a stalled TLS write
        //    cannot let the outbound buffer grow without limit).
        while out_buf.len() < RELAY_HIGH_WATER {
            match outbound_rx.try_recv() {
                Ok(chunk) => out_buf.extend_from_slice(&chunk),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    app_closed = true;
                    break;
                }
            }
        }

        // 2) Push outbound bytes into the TLS stream.
        if !out_buf.is_empty() {
            match tls.write(&out_buf) {
                Ok(0) => return Ok(()),
                Ok(count) => {
                    out_buf.drain(..count);
                }
                Err(error) if would_block(&error) => {}
                Err(error) => return Err(error),
            }
        }
        match tls.flush() {
            Ok(()) => {}
            Err(error) if would_block(&error) => {}
            Err(error) => return Err(error),
        }

        // 3) Once the app half is closed and everything is flushed, stop.
        if app_closed && out_buf.is_empty() {
            return Ok(());
        }

        // 4) Deliver any inbound chunk that did not fit last time.
        if let Some(chunk) = inbound_pending.take() {
            match inbound_tx.try_send(chunk) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(chunk)) => inbound_pending = Some(chunk),
                Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
            }
        }

        // 5) Read more from TLS only when the inbound queue has room; otherwise
        //    leave bytes in the socket (TCP backpressure) and keep servicing the
        //    outbound direction without a tight spin.
        if inbound_pending.is_none() {
            match tls.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(count) => match inbound_tx.try_send(buf[..count].to_vec()) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(chunk)) => inbound_pending = Some(chunk),
                    Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                },
                Err(error) if would_block(&error) => {}
                Err(error) => return Err(error),
            }
        } else {
            std::thread::sleep(BACKPRESSURE_POLL);
        }
    }
}

impl AsyncRead for BridgeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.leftover_pos < self.leftover.len() {
            let start = self.leftover_pos;
            let count = buf
                .remaining()
                .min(self.leftover.len() - start);
            buf.put_slice(&self.leftover[start..start + count]);
            self.leftover_pos += count;
            if self.leftover_pos == self.leftover.len() {
                self.leftover.clear();
                self.leftover_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        match self.inbound.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let count = buf.remaining().min(chunk.len());
                buf.put_slice(&chunk[..count]);
                if count < chunk.len() {
                    self.leftover = chunk;
                    self.leftover_pos = count;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for BridgeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &self.outbound {
            Some(sender) => match sender.send(buf.to_vec()) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(_) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "REALITY bridge closed",
                ))),
            },
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write after shutdown",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Dropping the sender signals end-of-stream to the worker, which then
        // sends a TLS close_notify.
        self.outbound = None;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc as std_mpsc;
    use tokio::io::AsyncReadExt;

    /// Transport that yields a fixed amount of readable bytes and records every
    /// write, so a test can observe the outbound direction independently.
    struct CountingTransport {
        remaining: usize,
        written: std_mpsc::Sender<Vec<u8>>,
    }

    impl Read for CountingTransport {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let count = buffer.len().min(self.remaining);
            buffer[..count].fill(42);
            self.remaining -= count;
            Ok(count)
        }
    }

    impl Write for CountingTransport {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.written
                .send(buffer.to_vec())
                .unwrap();
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_tls_flush_is_retried_without_new_app_data() {
        struct BufferedTransport {
            pending: Vec<u8>,
            blocked_once: bool,
            flushed: std_mpsc::Sender<Vec<u8>>,
        }

        impl Read for BufferedTransport {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::WouldBlock.into())
            }
        }

        impl Write for BufferedTransport {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                self.pending.extend_from_slice(buffer);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                if !self.pending.is_empty() {
                    if !self.blocked_once {
                        self.blocked_once = true;
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    self.flushed
                        .send(core::mem::take(&mut self.pending))
                        .unwrap();
                }
                Ok(())
            }
        }

        let (inbound_tx, _inbound_rx) = mpsc::channel::<Vec<u8>>(INBOUND_CHANNEL_CAP);
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (flushed, received) = std_mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut transport = BufferedTransport {
                pending: Vec::new(),
                blocked_once: false,
                flushed,
            };
            pump_io(&mut transport, &inbound_tx, &mut outbound_rx)
        });

        outbound_tx
            .send(b"pending".to_vec())
            .unwrap();
        let result = received.recv_timeout(Duration::from_secs(1));
        drop(outbound_tx);
        worker.join().unwrap().unwrap();
        assert_eq!(
            result.expect("pending TLS output must be retried without new app data"),
            b"pending"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_app_reader_does_not_block_outbound_data() {
        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(INBOUND_CHANNEL_CAP);
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (written, received) = std_mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut transport = CountingTransport {
                remaining: PUMP_BUFFER * 4,
                written,
            };
            pump_io(&mut transport, &inbound_tx, &mut outbound_rx)
        });

        // The app never reads inbound; once the inbound channel fills, the
        // worker must still deliver queued outbound writes.
        outbound_tx
            .send(b"first".to_vec())
            .unwrap();
        assert_eq!(
            received
                .recv_timeout(Duration::from_secs(1))
                .unwrap(),
            b"first"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        outbound_tx
            .send(b"next".to_vec())
            .unwrap();
        let next = received.recv_timeout(Duration::from_secs(1));

        // Draining the inbound side lets the worker resume reading the transport.
        let mut stream = BridgeStream {
            inbound: inbound_rx,
            leftover: Vec::new(),
            leftover_pos: 0,
            outbound: Some(outbound_tx.clone()),
        };
        let mut drained = 0usize;
        let mut scratch = vec![0u8; PUMP_BUFFER];
        while drained < PUMP_BUFFER {
            match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut scratch)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(count)) => drained += count,
                Ok(Err(_)) => break,
            }
        }

        drop(outbound_tx);
        drop(stream);
        worker.join().unwrap().unwrap();
        assert_eq!(
            next.expect("outbound traffic must progress even while the app is not reading"),
            b"next"
        );
        assert!(drained >= PUMP_BUFFER);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inbound_bytes_reach_the_async_reader_in_order() {
        struct OnceTransport {
            payload: Vec<u8>,
        }

        impl Read for OnceTransport {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.payload.is_empty() {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let count = buffer.len().min(self.payload.len());
                buffer[..count].copy_from_slice(&self.payload[..count]);
                self.payload.drain(..count);
                Ok(count)
            }
        }

        impl Write for OnceTransport {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                Ok(buffer.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(INBOUND_CHANNEL_CAP);
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let worker = std::thread::spawn(move || {
            let mut transport = OnceTransport {
                payload: b"hello world".to_vec(),
            };
            pump_io(&mut transport, &inbound_tx, &mut outbound_rx)
        });

        let mut stream = BridgeStream {
            inbound: inbound_rx,
            leftover: Vec::new(),
            leftover_pos: 0,
            outbound: Some(outbound_tx.clone()),
        };
        let mut got = Vec::new();
        while got.len() < b"hello world".len() {
            let mut scratch = [0u8; 4];
            let count = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut scratch))
                .await
                .expect("inbound data must arrive")
                .expect("read must succeed");
            assert_ne!(count, 0);
            got.extend_from_slice(&scratch[..count]);
        }
        assert_eq!(got, b"hello world");

        drop(outbound_tx);
        drop(stream);
        worker.join().unwrap().unwrap();
    }
}
