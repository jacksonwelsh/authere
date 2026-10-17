//! TCP listener + per-connection task. The connection handler is generic over any
//! `AsyncRead + AsyncWrite` stream so that a future LDAPS listener can reuse it verbatim
//! by wrapping `TcpStream` in `tokio_rustls::server::TlsStream`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use ldap3_proto::LdapCodec;
use ldap3_proto::proto::{LdapMsg, LdapOp, LdapResult, LdapResultCode};
use ldap3_proto::simple::{DisconnectionNotice, ServerOps};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::{error, info, warn};

use crate::AppState;
use crate::settings::load_ldap_config;

use super::handler::{BindState, handle_bind, handle_search};

const IO_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CONNECTIONS: usize = 128;
const MAX_BER_DEPTH: usize = 32;

fn invalid_frame() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, "LDAP frame too large or invalid")
}

/// Read only a definite-length BER header, without allocating for its declared body.
fn ber_header(buf: &[u8]) -> Result<Option<(usize, usize)>, std::io::Error> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let length_byte = buf[1];
    if length_byte & 0x80 == 0 {
        return Ok(Some((2, usize::from(length_byte))));
    }
    let octets = usize::from(length_byte & 0x7f);
    if octets == 0 || octets > std::mem::size_of::<usize>() {
        return Err(invalid_frame());
    }
    if buf.len() < 2 + octets {
        return Ok(None);
    }
    let mut length = 0usize;
    for byte in &buf[2..2 + octets] {
        length = length.checked_mul(256).and_then(|n| n.checked_add(usize::from(*byte))).ok_or_else(invalid_frame)?;
    }
    Ok(Some((2 + octets, length)))
}

/// Walk constructed values with an explicit, bounded stack before the upstream recursive
/// parser sees them. A small frame can still contain thousands of nested containers.
fn validate_ber_structure(frame: &[u8]) -> Result<(), std::io::Error> {
    let mut ends = vec![frame.len()];
    let mut position = 0usize;
    while let Some(&parent_end) = ends.last() {
        if position == parent_end {
            ends.pop();
            continue;
        }
        let remaining = frame.get(position..parent_end).ok_or_else(invalid_frame)?;
        let (header, body) = ber_header(remaining)?.ok_or_else(invalid_frame)?;
        let body_start = position.checked_add(header).ok_or_else(invalid_frame)?;
        let body_end = body_start.checked_add(body).ok_or_else(invalid_frame)?;
        if body_end > parent_end {
            return Err(invalid_frame());
        }
        if remaining[0] & 0x20 != 0 {
            if ends.len() >= MAX_BER_DEPTH {
                return Err(invalid_frame());
            }
            ends.push(body_end);
            position = body_start;
        } else {
            position = body_end;
        }
    }
    Ok(())
}

/// Reject oversized BER frames before asking the protocol parser to buffer their body.
/// The upstream codec checks the size only after a complete message has been decoded.
#[derive(Default)]
struct BoundedLdapCodec(LdapCodec);

impl Decoder for BoundedLdapCodec {
    type Item = LdapMsg;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<LdapMsg>, Self::Error> {
        let Some((header_len, body_len)) = ber_header(buf)? else {
            return Ok(None);
        };
        let frame_len = body_len.checked_add(header_len).ok_or_else(invalid_frame)?;
        if frame_len > ldap3_proto::DEFAULT_MAX_BER_SIZE {
            return Err(invalid_frame());
        }
        if buf.len() < frame_len {
            return Ok(None);
        }
        validate_ber_structure(&buf[..frame_len])?;
        self.0.decode(buf)
    }
}

impl Encoder<LdapMsg> for BoundedLdapCodec {
    type Error = std::io::Error;

    fn encode(&mut self, msg: LdapMsg, buf: &mut BytesMut) -> Result<(), Self::Error> {
        self.0.encode(msg, buf)
    }
}

/// Start the LDAP TCP listener. Returns when the listener is unable to accept further
/// connections (e.g. bind failure, fatal I/O error). Usually called from a spawned task.
pub async fn run(state: AppState) -> std::io::Result<()> {
    let cfg = {
        let mut conn = state
            .db_pool
            .acquire()
            .await
            .map_err(|e| std::io::Error::other(format!("acquire db: {e}")))?;
        load_ldap_config(&mut conn)
            .await
            .map_err(|e| std::io::Error::other(format!("load ldap config: {e:?}")))?
    };
    let listener = TcpListener::bind(cfg.bind_address).await?;
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    info!(addr = %cfg.bind_address, base_dn = %cfg.base_dn, "ldap listener started");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                error!(error = %e, "ldap: accept failed");
                continue;
            }
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_connection(stream, state, peer).await {
                warn!(peer = %peer, error = %e, "ldap connection terminated with error");
            }
        });
    }
}

/// Handle a single LDAP connection. Generic over the stream type — plaintext today, TLS
/// later without changes here.
pub async fn handle_connection<S>(
    stream: S,
    state: AppState,
    peer: SocketAddr,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut cfg = {
        let mut conn = state
            .db_pool
            .acquire()
            .await
            .map_err(|e| std::io::Error::other(format!("acquire db: {e}")))?;
        load_ldap_config(&mut conn)
            .await
            .map_err(|e| std::io::Error::other(format!("load ldap config: {e:?}")))?
    };

    let mut framed = Framed::new(stream, BoundedLdapCodec::default());
    let mut bind_state = BindState::Anonymous;

    while let Ok(Some(msg)) = timeout(IO_TIMEOUT, framed.next()).await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                warn!(peer = %peer, error = %e, "ldap: decode error");
                break;
            }
        };

        let current_cfg = {
            let mut conn = state.db_pool.acquire().await.map_err(std::io::Error::other)?;
            load_ldap_config(&mut conn).await.map_err(|e| std::io::Error::other(format!("load ldap config: {e:?}")))?
        };
        if !current_cfg.enabled {
            break;
        }
        if current_cfg.service_password_hash != cfg.service_password_hash
            || current_cfg.password_mode != cfg.password_mode
            || current_cfg.base_dn != cfg.base_dn
        {
            bind_state = BindState::Anonymous;
        }
        cfg = current_cfg;

        let ops = match ServerOps::try_from(msg.clone()) {
            Ok(o) => o,
            Err(_) => {
                // Unsupported op (Add/Modify/Delete/ModDN/Abandon/etc) — answer with a
                // protocol error so clients see something meaningful.
                let resp = unsupported_response(&msg);
                if let Some(r) = resp {
                    if !matches!(timeout(IO_TIMEOUT, framed.send(r)).await, Ok(Ok(()))) {
                        break;
                    }
                }
                continue;
            }
        };

        match ops {
            ServerOps::SimpleBind(req) => {
                let (resp, new_state) = handle_bind(&req, &cfg, &state, peer.ip()).await;
                bind_state = new_state;
                if !matches!(timeout(IO_TIMEOUT, framed.send(resp)).await, Ok(Ok(()))) {
                    break;
                }
            }
            ServerOps::Search(req) => {
                let resps = handle_search(&req, &cfg, &state, &bind_state).await;
                for r in resps {
                    if !matches!(timeout(IO_TIMEOUT, framed.send(r)).await, Ok(Ok(()))) {
                        return Ok(());
                    }
                }
            }
            ServerOps::Unbind(_) => break,
            ServerOps::Whoami(req) => {
                let authzid = match &bind_state {
                    BindState::Anonymous => String::new(),
                    BindState::Service => format!("dn:{}", cfg.service_account_dn()),
                    BindState::User(_) => String::from("dn:"),
                };
                if !matches!(timeout(IO_TIMEOUT, framed.send(req.gen_success(&authzid))).await, Ok(Ok(()))) {
                    break;
                }
            }
            ServerOps::Compare(req) => {
                if !matches!(timeout(IO_TIMEOUT, framed.send(req.gen_compare_false())).await, Ok(Ok(()))) {
                    break;
                }
            }
        }
    }

    // Best-effort disconnection notice; ignore errors since the socket might already be gone.
    let _ = timeout(IO_TIMEOUT, framed.send(DisconnectionNotice::r#gen(LdapResultCode::Success, "bye"))).await;
    Ok(())
}

fn unsupported_response(msg: &LdapMsg) -> Option<LdapMsg> {
    let result = LdapResult {
        code: LdapResultCode::UnwillingToPerform,
        matcheddn: String::new(),
        message: "operation not supported".to_string(),
        referral: Vec::new(),
    };
    let op = match &msg.op {
        LdapOp::AddRequest(_) => LdapOp::AddResponse(result),
        LdapOp::ModifyRequest(_) => LdapOp::ModifyResponse(result),
        LdapOp::DelRequest(_) => LdapOp::DelResponse(result),
        LdapOp::ModifyDNRequest(_) => LdapOp::ModifyDNResponse(result),
        LdapOp::ExtendedRequest(_) => return None,
        _ => return None,
    };
    Some(LdapMsg {
        msgid: msg.msgid,
        op,
        ctrl: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_frame_before_body_arrives() {
        let mut codec = BoundedLdapCodec::default();
        let mut bytes = BytesMut::from(&[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff][..]);
        assert!(codec.decode(&mut bytes).is_err());
    }

    #[test]
    fn rejects_indefinite_or_overflowing_lengths() {
        for bytes in [&[0x30, 0x80][..], &[0x30, 0xff][..]] {
            assert!(BoundedLdapCodec::default().decode(&mut BytesMut::from(bytes)).is_err());
        }
    }

    #[test]
    fn buffers_small_partial_messages() {
        let mut bytes = BytesMut::from(&[0x30, 0x10, 0x02][..]);
        assert!(BoundedLdapCodec::default().decode(&mut bytes).unwrap().is_none());
    }

    #[test]
    fn rejects_excessive_nesting_before_recursive_protocol_parsing() {
        let mut frame = vec![0x04, 0x00];
        for _ in 0..MAX_BER_DEPTH + 1 {
            // This fixture remains below128 bytes, so each container has a short length.
            let mut parent = vec![0x30, frame.len() as u8];
            parent.extend(frame);
            frame = parent;
        }
        assert!(BoundedLdapCodec::default().decode(&mut BytesMut::from(frame.as_slice())).is_err());
    }

    #[test]
    fn ber_guard_accepts_siblings_and_rejects_a_child_outside_its_parent() {
        assert!(validate_ber_structure(&[0x30, 0x06, 0x04, 0x01, 0xff, 0x04, 0x01, 0xff]).is_ok());
        assert!(validate_ber_structure(&[0x30, 0x03, 0x04, 0x04, 0xff]).is_err());
        assert!(validate_ber_structure(&[0x30, 0x02, 0x30, 0x80]).is_err());
    }
}
