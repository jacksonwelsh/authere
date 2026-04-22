//! TCP listener + per-connection task. The connection handler is generic over any
//! `AsyncRead + AsyncWrite` stream so that a future LDAPS listener can reuse it verbatim
//! by wrapping `TcpStream` in `tokio_rustls::server::TlsStream`.

use std::net::SocketAddr;

use futures_util::{SinkExt, StreamExt};
use ldap3_proto::LdapCodec;
use ldap3_proto::proto::{LdapMsg, LdapOp, LdapResult, LdapResultCode};
use ldap3_proto::simple::{DisconnectionNotice, ServerOps};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_util::codec::Framed;
use tracing::{error, info, warn};

use crate::AppState;
use crate::settings::load_ldap_config;

use super::handler::{BindState, handle_bind, handle_search};

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
    info!(addr = %cfg.bind_address, base_dn = %cfg.base_dn, "ldap listener started");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                error!(error = %e, "ldap: accept failed");
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
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
    // Per-connection rate limit to slow down credential stuffing. If the peer is over the
    // limit we refuse the connection outright.
    if state
        .ldap_bind_rate_limiter
        .check(peer.ip())
        .await
        .is_err()
    {
        warn!(peer = %peer, "ldap: connection rejected due to rate limit");
        return Ok(());
    }

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

    let mut framed = Framed::new(stream, LdapCodec::default());
    let mut bind_state = BindState::Anonymous;

    while let Some(msg) = framed.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                warn!(peer = %peer, error = %e, "ldap: decode error");
                break;
            }
        };

        let ops = match ServerOps::try_from(msg.clone()) {
            Ok(o) => o,
            Err(_) => {
                // Unsupported op (Add/Modify/Delete/ModDN/Abandon/etc) — answer with a
                // protocol error so clients see something meaningful.
                let resp = unsupported_response(&msg);
                if let Some(r) = resp {
                    if framed.send(r).await.is_err() {
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
                if framed.send(resp).await.is_err() {
                    break;
                }
            }
            ServerOps::Search(req) => {
                let resps = handle_search(&req, &cfg, &state, &bind_state).await;
                for r in resps {
                    if framed.send(r).await.is_err() {
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
                if framed.send(req.gen_success(&authzid)).await.is_err() {
                    break;
                }
            }
            ServerOps::Compare(req) => {
                if framed.send(req.gen_compare_false()).await.is_err() {
                    break;
                }
            }
        }
    }

    // Best-effort disconnection notice; ignore errors since the socket might already be gone.
    let _ = framed
        .send(DisconnectionNotice::r#gen(LdapResultCode::Success, "bye"))
        .await;
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
