use sfio_rustls_config::{ClientNameVerification, MinProtocolVersion, ServerNameVerification};
use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("certs")
}

fn self_signed_dir() -> PathBuf {
    certs_dir().join("self-signed")
}

fn ca_dir() -> PathBuf {
    certs_dir().join("authority")
}

async fn connect() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    fn local_host(port: u16) -> SocketAddr {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into()
    }

    let listener = tokio::net::TcpListener::bind(local_host(0)).await.unwrap();
    let assigned_port = listener.local_addr().unwrap().port();
    let client = tokio::net::TcpStream::connect(local_host(assigned_port))
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();

    (client, server)
}

#[tokio::test]
async fn self_signed_verifier_works() {
    let server_config = sfio_rustls_config::server::self_signed(
        MinProtocolVersion::V1_3,
        &self_signed_dir().join("bill.crt"),
        &self_signed_dir().join("jim.crt"),
        &self_signed_dir().join("jim.key"),
        None,
    )
    .unwrap();

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
    let server_config = sfio_rustls_config::server::self_signed(
        MinProtocolVersion::V1_3,
        &self_signed_dir().join("bill.crt"),
        &self_signed_dir().join("jim.crt"),
        &self_signed_dir().join("jim.key"),
        None,
    )
    .unwrap();

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
    let _client_err = connector.connect(name, client).await.unwrap_err();
    let _server_err = server_task.await.unwrap().unwrap_err();
}

#[tokio::test]
async fn can_verify_server_name_in_san_extension() {
    client_can_verify_server_name("server42", ClientNameVerification::None, ServerNameVerification::Verify).await;
}

#[tokio::test]
async fn can_verify_server_name_in_common_name() {
    client_can_verify_server_name("myserver", ClientNameVerification::None, ServerNameVerification::Verify).await;
}

async fn client_can_verify_server_name(
    name: &'static str,
    client_name_verification: ClientNameVerification,
    server_name_verification: ServerNameVerification,
) {
    let server_config = sfio_rustls_config::server::authority(
        MinProtocolVersion::V1_3,
        client_name_verification,
        &ca_dir().join("ca.crt"),
        &ca_dir().join("server.crt"),
        &ca_dir().join("server.key"),
        None,
    )
    .unwrap();

    let client_config = sfio_rustls_config::client::authority(
        MinProtocolVersion::V1_3,
        server_name_verification,
        &ca_dir().join("ca.crt"),
        &ca_dir().join("client.crt"),
        &ca_dir().join("client.key"),
        None,
    )
    .unwrap();

    let (client, server) = connect().await;

    let connector = TlsConnector::from(Arc::new(client_config));
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let server_task = tokio::spawn(acceptor.accept(server));

    // doesn't matter what this is b/c it won't be checked
    let name: ServerName = name.try_into().unwrap();

    let _client = connector.connect(name, client).await.unwrap();
    let _server = server_task.await.unwrap();
}
