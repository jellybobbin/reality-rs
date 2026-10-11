use anytls::{
    PanelSyncClient, PanelSyncConfig, Stream as AnytlsStream, TrafficAudit, TrafficAuditPtr, UotMode, uot_get_packet_from_stream,
};
use core::pin::Pin;
use core::task::{Context, Poll};
use socks5_impl::protocol::Address;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use uuid::Uuid;

#[derive(Clone)]
pub struct PanelSync {
    audit: TrafficAuditPtr,
    enabled: bool,
}

impl PanelSync {
    pub async fn start(config: Option<PanelSyncConfig>) -> std::io::Result<Self> {
        let config = Self::resolve_config(config).map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        let audit: TrafficAuditPtr = Arc::new(tokio::sync::Mutex::new(TrafficAudit::new()));
        let enabled = config.is_some();
        if let Some(config) = config {
            let mut client = PanelSyncClient::new(config);
            client.sync_initial(&audit).await?;
            let task_audit = Arc::clone(&audit);
            tokio::spawn(async move {
                client.run(task_audit, anytls::CancellationToken::new()).await;
            });
        }
        Ok(Self { audit, enabled })
    }

    pub async fn authorizes(&self, client_id: Option<Uuid>) -> bool {
        if !self.enabled {
            return true;
        }
        match client_id {
            Some(client_id) => self.audit.lock().await.is_enabled(&client_id),
            None => false,
        }
    }

    pub async fn record_traffic(&self, client_id: Option<Uuid>, upstream: u64, downstream: u64) {
        if self.enabled
            && let Some(client_id) = client_id
        {
            let mut audit = self.audit.lock().await;
            audit.add_upstream(&client_id, upstream);
            audit.add_downstream(&client_id, downstream);
        }
    }

    pub async fn relay_tcp<A, B>(
        &self,
        peer: &mut A,
        tunnel: &mut B,
        client_id: Option<Uuid>,
    ) -> Result<(u64, u64), anytls::relay::RelayError>
    where
        A: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        let mut counted_peer = CountedIo::new(peer);
        let mut counted_tunnel = CountedIo::new(tunnel);
        let result = anytls::relay::copy_bidirectional(&mut counted_peer, &mut counted_tunnel).await;
        self.record_traffic(client_id, counted_tunnel.written, counted_peer.written).await;
        result
    }

    pub async fn relay_uot(
        &self,
        udp: &UdpSocket,
        stream: &AnytlsStream,
        reader: &mut anytls::StreamIo,
        mode: UotMode,
        client_id: Option<Uuid>,
    ) -> Result<(), UotRelayError> {
        let outbound = async {
            loop {
                let (destination, payload) = uot_get_packet_from_stream(mode, reader)
                    .await
                    .map_err(|error| UotRelayError { peer: true, error })?;
                let sent = match mode {
                    UotMode::Datagram => {
                        let destination = destination.ok_or_else(|| UotRelayError {
                            peer: true,
                            error: std::io::Error::new(std::io::ErrorKind::InvalidData, "UoT datagram missing destination"),
                        })?;
                        udp.send_to(&payload, destination.to_string())
                            .await
                            .map_err(|error| UotRelayError { peer: false, error })?
                    }
                    UotMode::Connected => udp.send(&payload).await.map_err(|error| UotRelayError { peer: false, error })?,
                };
                self.record_traffic(client_id, sent as u64, 0).await;
            }
            #[allow(unreachable_code)]
            Ok::<(), UotRelayError>(())
        };
        let inbound = async {
            let mut buffer = vec![0; 65_535];
            loop {
                let (count, source) = match mode {
                    UotMode::Datagram => {
                        let (count, source) = udp
                            .recv_from(&mut buffer)
                            .await
                            .map_err(|error| UotRelayError { peer: false, error })?;
                        (count, Some(Address::from(source)))
                    }
                    UotMode::Connected => {
                        let count = udp.recv(&mut buffer).await.map_err(|error| UotRelayError { peer: false, error })?;
                        (count, None)
                    }
                };
                let frame = anytls::uot_encode_packet(mode, source.as_ref(), &buffer[..count])
                    .map_err(|error| UotRelayError { peer: false, error })?;
                Self::write_stream_all(stream, &frame)
                    .await
                    .map_err(|error| UotRelayError { peer: true, error })?;
                self.record_traffic(client_id, 0, count as u64).await;
            }
            #[allow(unreachable_code)]
            Ok::<(), UotRelayError>(())
        };
        tokio::select! {
            result = outbound => result,
            result = inbound => result,
        }
    }

    async fn write_stream_all(stream: &AnytlsStream, mut bytes: &[u8]) -> std::io::Result<()> {
        while !bytes.is_empty() {
            let written = stream.write(bytes).await?;
            if written == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "failed to write UoT stream"));
            }
            bytes = &bytes[written..];
        }
        Ok(())
    }

    pub fn resolve_config(config: Option<PanelSyncConfig>) -> anyhow::Result<Option<PanelSyncConfig>> {
        let Some(config) = config else {
            return Ok(None);
        };
        if !config.is_configured() {
            match (config.webapi_url, config.webapi_token, config.node_id) {
                (None, None, None) => return Ok(None),
                _ => anyhow::bail!("panelSync.webapi_url, panelSync.webapi_token, and panelSync.node_id must be set together"),
            }
        }
        Ok(Some(config))
    }
}

struct CountedIo<T> {
    inner: T,
    written: u64,
}

impl<T> CountedIo<T> {
    fn new(inner: T) -> Self {
        Self { inner, written: 0 }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountedIo<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountedIo<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result {
            self.written = self.written.saturating_add(*written as u64);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug)]
pub struct UotRelayError {
    peer: bool,
    error: std::io::Error,
}

impl UotRelayError {
    pub fn is_peer_disconnect(&self) -> bool {
        self.peer && (self.error.kind() == std::io::ErrorKind::UnexpectedEof || anytls::relay::is_peer_disconnect(&self.error))
    }
}

impl core::fmt::Display for UotRelayError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}", self.error)
    }
}

impl core::error::Error for UotRelayError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.error)
    }
}
