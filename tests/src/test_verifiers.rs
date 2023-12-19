use sfio_rustls_config::{ClientNameVerification, MinProtocolVersion, ServerNameVerification};
use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use rustls::ServerConfig;
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
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
    let client = TcpStream::connect(local_host(assigned_port))
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();

    (client, server)
}

fn get_self_signed_server_config() -> ServerConfig {
    sfio_rustls_config::server::self_signed(
        MinProtocolVersion::V1_3,
        &self_signed_dir().join("bill.crt"),
        &self_signed_dir().join("jim.crt"),
        &self_signed_dir().join("jim.key"),
        None,
    ).unwrap()
}

#[tokio::test]
async fn self_signed_verifier_works() {

    let server_config = get_self_signed_server_config();

    // this config pairs with the server config, i.e. jim and bill want to talk
    let client_config = sfio_rustls_config::client::self_signed(
        MinProtocolVersion::V1_3,
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
        MinProtocolVersion::V1_3,
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
async fn can_verify_server_name_in_san_extension() {
    let (client, server) = perform_ca_handshake(
        "server42",
        ca_san_dir(),
        ClientNameVerification::None,
        ServerNameVerification::Verify,
    )
    .await;
    client.expect("client connection failed");
    server.expect("server connection failed");
}

#[tokio::test]
async fn does_not_verify_server_name_in_common_name_when_san_is_present() {
    let (client, server) = perform_ca_handshake(
        "myserver",
        ca_san_dir(),
        ClientNameVerification::None,
        ServerNameVerification::Verify,
    )
    .await;
    client.expect_err("client did NOT fail as expected");
    server.expect_err("server did NOT fail as expected");
}

#[tokio::test]
async fn can_verify_server_name_in_common_name_when_san_is_absent() {
    let (client, server) = perform_ca_handshake(
        "myserver",
        ca_subject_only_dir(),
        ClientNameVerification::None,
        ServerNameVerification::Verify,
    )
    .await;
    client.unwrap();
    server.unwrap();
}


type ClientHandshakeResult = std::io::Result<tokio_rustls::client::TlsStream<TcpStream>>;
type ServerHandshakeResult = std::io::Result<tokio_rustls::server::TlsStream<TcpStream>>;

async fn perform_ca_handshake(
    name: &'static str,
    path: PathBuf,
    client_name_verification: ClientNameVerification,
    server_name_verification: ServerNameVerification,
) -> (ClientHandshakeResult, ServerHandshakeResult) {
    let server_config = sfio_rustls_config::server::authority(
        MinProtocolVersion::V1_3,
        client_name_verification,
        &path.join("ca.crt"),
        &path.join("server.crt"),
        &path.join("server.key"),
        None,
    )
    .unwrap();

    let client_config = sfio_rustls_config::client::authority(
        MinProtocolVersion::V1_3,
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

    // doesn't matter what this is b/c it won't be checked
    let name: ServerName = name.try_into().unwrap();

    let client = connector.connect(name, client).await;
    let server = server_task.await.unwrap();

    (client, server)
}
