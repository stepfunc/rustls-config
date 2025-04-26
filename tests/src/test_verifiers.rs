use sfio_rustls_config::{ClientNameVerification, ProtocolVersions, ServerNameVerification};
use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("certs")
}

fn self_signed_dir() -> PathBuf {
    certs_dir().join("self-signed")
}

fn ca_san_dir() -> PathBuf {
    certs_dir().join("authority").join("san")
}

fn ca_subject_only_dir() -> PathBuf {
    certs_dir().join("authority").join("subject_cn_only")
}

async fn connect() -> (TcpStream, TcpStream) {
    fn local_host(port: u16) -> SocketAddr {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()
    }

    let listener = tokio::net::TcpListener::bind(local_host(0)).await.unwrap();
    let assigned_port = listener.local_addr().unwrap().port();
    let client = TcpStream::connect(local_host(assigned_port)).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();

    (client, server)
}

fn get_self_signed_server_config() -> ServerConfig {
    sfio_rustls_config::server::self_signed(
        ProtocolVersions::v13_only(),
        &self_signed_dir().join("bill.crt"),
        &self_signed_dir().join("jim.crt"),
        &self_signed_dir().join("jim.key"),
        None,
    )
    .unwrap()
}

#[tokio::test]
async fn self_signed_verifier_works() {
    let server_config = get_self_signed_server_config();

    // this config pairs with the server config, i.e. jim and bill want to talk
    let client_config = sfio_rustls_config::client::self_signed(
        ProtocolVersions::v13_only(),
        &self_signed_dir().join("jim.crt"),
        &self_signed_dir().join("bill.crt"),
        &self_signed_dir().join("bill.key"),
        None,
    )
    .unwrap();

    let (client, server) = connect().await;

    let connector = TlsConnector::from(Arc::new(client_config));
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let server_task = tokio::spawn(acceptor.accept(server));

    // doesn't matter what this is b/c it won't be checked
    let name: ServerName = "whatever".try_into().unwrap();

    let _client = connector.connect(name, client).await.unwrap();
    let _server = server_task.await.unwrap();
}

#[tokio::test]
async fn self_signed_verifier_rejects_wrong_cert() {
    let server_config = get_self_signed_server_config();

    // this client config conflicts with the server config
    let client_config = sfio_rustls_config::client::self_signed(
        ProtocolVersions::v13_only(),
        &self_signed_dir().join("ted.crt"),
        &self_signed_dir().join("bill.crt"),
        &self_signed_dir().join("bill.key"),
        None,
    )
    .unwrap();

    let (client, server) = connect().await;

    let connector = TlsConnector::from(Arc::new(client_config));
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let server_task = tokio::spawn(acceptor.accept(server));

    // doesn't matter what this is b/c it won't be checked
    let name: ServerName = "whatever".try_into().unwrap();

    // both client and server should fail
    connector.connect(name, client).await.unwrap_err();
    server_task.await.unwrap().unwrap_err();
}

#[tokio::test]
async fn can_disable_server_name_verification_entirely() {
    perform_ca_handshake(
        "wrong_name",
        ProtocolVersions::v13_only(),
        ca_san_dir(),
        ClientNameVerification::None,
        ServerNameVerification::DisableNameVerification,
    )
    .await
    .assert_success();
}

#[tokio::test]
async fn can_verify_server_name_in_san_extension() {
    perform_ca_handshake(
        "server42",
        ProtocolVersions::v13_only(),
        ca_san_dir(),
        ClientNameVerification::None,
        ServerNameVerification::SanOrCommonName,
    )
    .await
    .assert_success();
}

#[tokio::test]
async fn does_not_verify_server_name_in_common_name_when_san_is_present() {
    perform_ca_handshake(
        "myserver",
        ProtocolVersions::v13_only(),
        ca_san_dir(),
        ClientNameVerification::None,
        ServerNameVerification::SanOrCommonName,
    )
    .await
    .assert_failure()
}

#[tokio::test]
async fn can_verify_server_name_in_common_name_when_san_is_absent() {
    perform_ca_handshake(
        "myserver",
        ProtocolVersions::v13_only(),
        ca_subject_only_dir(),
        ClientNameVerification::None,
        ServerNameVerification::SanOrCommonName,
    )
    .await
    .assert_success();
}

#[tokio::test]
async fn rejects_wrong_client_name() {
    perform_ca_handshake(
        "whatever",
        ProtocolVersions::v12_only(),
        ca_subject_only_dir(),
        ClientNameVerification::SanExtOnly("myclient".try_into().unwrap()),
        ServerNameVerification::DisableNameVerification,
    )
    .await
    .assert_failure();
}

#[must_use]
struct HandshakeResult {
    client: std::io::Result<tokio_rustls::client::TlsStream<TcpStream>>,
    server: std::io::Result<tokio_rustls::server::TlsStream<TcpStream>>,
}

impl HandshakeResult {
    fn assert_success(self) {
        self.server.expect("server handshake failed");
        self.client.expect("client handshake failed");
    }

    fn assert_failure(self) {
        self.server.expect_err("server handshake did NOT fail");
        self.client.expect_err("client handshake did NOT fail");
    }
}

async fn perform_ca_handshake(
    name: &'static str,
    versions: ProtocolVersions,
    path: PathBuf,
    client_name_verification: ClientNameVerification,
    server_name_verification: ServerNameVerification,
) -> HandshakeResult {
    let server_config = sfio_rustls_config::server::authority(
        versions,
        client_name_verification,
        &path.join("ca.crt"),
        &path.join("server.crt"),
        &path.join("server.key"),
        None,
    )
    .unwrap();

    let client_config = sfio_rustls_config::client::authority(
        versions,
        server_name_verification,
        &path.join("ca.crt"),
        &path.join("client.crt"),
        &path.join("client.key"),
        None,
    )
    .unwrap();

    let (client, server) = connect().await;

    let connector = TlsConnector::from(Arc::new(client_config));
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let server_task = tokio::spawn(acceptor.accept(server));

    let name: ServerName = name.try_into().unwrap();

    let client = connector.connect(name, client).await;
    let server = server_task.await.unwrap();

    HandshakeResult { client, server }
}
