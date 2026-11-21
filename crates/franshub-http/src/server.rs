//! Serving a router over plain TCP or rustls, with graceful shutdown.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::body::Body;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tower::ServiceExt;

/// PEM files of a TLS listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsFiles {
    /// Certificate chain, leaf first.
    pub cert_file: PathBuf,
    /// Private key (PKCS#8, PKCS#1 or SEC1).
    pub key_file: PathBuf,
    /// CA bundle for client certificates; `None` turns client certificates off.
    pub client_ca_file: Option<PathBuf>,
    /// With a client CA: refuse connections without a valid client certificate.
    pub client_auth_required: bool,
}

/// SHA-256 (lowercase hex) of the client certificate of a TLS connection, inserted as a request
/// extension when the client presented one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientCertFingerprint(pub String);

/// A rustls server configuration (ring provider, TLS 1.2 and 1.3, ALPN h2 and http/1.1) with
/// optional client certificates.
pub fn server_config(files: &TlsFiles) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&files.cert_file)
        .with_context(|| format!("reading {}", files.cert_file.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("parsing {}", files.cert_file.display()))?;
    if certs.is_empty() {
        anyhow::bail!("{} contains no certificates", files.cert_file.display());
    }
    let key = PrivateKeyDer::from_pem_file(&files.key_file)
        .with_context(|| format!("reading the private key {}", files.key_file.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    let mut cfg = match &files.client_ca_file {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for c in CertificateDer::pem_file_iter(ca)
                .with_context(|| format!("reading {}", ca.display()))?
            {
                roots.add(c.with_context(|| format!("parsing {}", ca.display()))?)?;
            }
            let v = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
            let v = if files.client_auth_required {
                v.build()?
            } else {
                v.allow_unauthenticated().build()?
            };
            builder
                .with_client_cert_verifier(v)
                .with_single_cert(certs, key)?
        }
        None => builder.with_no_client_auth().with_single_cert(certs, key)?,
    };
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Timeouts of [`serve`].
#[derive(Clone, Copy, Debug)]
pub struct ServeOptions {
    /// Longest wait for the request head of an HTTP/1 connection.
    pub header_read_timeout: Duration,
    /// Longest TLS handshake.
    pub handshake_timeout: Duration,
    /// After shutdown starts, how long open connections may finish.
    pub drain: Duration,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            header_read_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            drain: Duration::from_secs(20),
        }
    }
}

async fn connection<I>(
    io: I,
    router: Router,
    fingerprint: Option<String>,
    builder: Builder<TokioExecutor>,
    watcher: hyper_util::server::graceful::Watcher,
    peer: std::net::SocketAddr,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = tower::service_fn(move |mut req: hyper::Request<Incoming>| {
        if let Some(fp) = &fingerprint {
            req.extensions_mut()
                .insert(ClientCertFingerprint(fp.clone()));
        }
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        router.clone().oneshot(req.map(Body::new))
    });
    let conn = builder
        .serve_connection_with_upgrades(io, TowerToHyperService::new(svc))
        .into_owned();
    if let Err(e) = watcher.watch(conn).await {
        tracing::debug!(%peer, error = %e, "connection closed with error");
    }
}

/// Serves `router` on `listener` until `shutdown` completes, then stops accepting and waits up to
/// `opts.drain` for open connections. With `tls`, connections are TLS and a client certificate's
/// fingerprint is available as [`ClientCertFingerprint`]; the peer address is available as
/// `ConnectInfo<SocketAddr>`.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown: impl Future<Output = ()> + Send,
    opts: ServeOptions,
) {
    let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(opts.header_read_timeout);
    builder.http2().timer(TokioTimer::new());
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            _ = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    metrics::counter!("http_accept_errors_total").increment(1);
                    tracing::warn!(error = %e, "accept failed; pausing");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            },
        };
        let router = router.clone();
        let builder = builder.clone();
        let watcher = graceful.watcher();
        match acceptor.clone() {
            None => {
                tokio::spawn(connection(
                    TokioIo::new(stream),
                    router,
                    None,
                    builder,
                    watcher,
                    peer,
                ));
            }
            Some(acceptor) => {
                let handshake = opts.handshake_timeout;
                tokio::spawn(async move {
                    let tls = match tokio::time::timeout(handshake, acceptor.accept(stream)).await {
                        Ok(Ok(t)) => t,
                        Ok(Err(e)) => {
                            metrics::counter!("http_tls_handshake_failures_total").increment(1);
                            tracing::debug!(%peer, error = %e, "TLS handshake failed");
                            return;
                        }
                        Err(_) => {
                            metrics::counter!("http_tls_handshake_failures_total").increment(1);
                            return;
                        }
                    };
                    let fingerprint = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|c| c.first())
                        .map(|c| hex::encode(Sha256::digest(c.as_ref())));
                    connection(
                        TokioIo::new(tls),
                        router,
                        fingerprint,
                        builder,
                        watcher,
                        peer,
                    )
                    .await;
                });
            }
        }
    }
    drop(listener);
    if tokio::time::timeout(opts.drain, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("open connections did not finish within the drain period");
    }
}

/// Completes on Ctrl-C or, on Unix, SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}
