use super::*;
use crate::config::ProxyConfig;
use tokio::io::{duplex, AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn bad_client_probe_is_forwarded_verbatim_to_mask_backend() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = b"GET / HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec();
    let backend_reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec();

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = vec![0u8; probe.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, probe);
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_proxy_protocol = 0;

    let peer: SocketAddr = "203.0.113.10:42424".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

    let (client_reader, _client_writer) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(2048);

    let beobachten = BeobachtenStore::new();
    handle_bad_client(
        client_reader,
        client_visible_writer,
        &probe,
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    let mut observed = vec![0u8; backend_reply.len()];
    client_visible_reader.read_exact(&mut observed).await.unwrap();
    assert_eq!(observed, backend_reply);
    accept_task.await.unwrap();
}

#[tokio::test]
async fn tls_scanner_probe_keeps_http_like_fallback_surface() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = vec![0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04];
    let backend_reply = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".to_vec();

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        let backend_reply = backend_reply.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = vec![0u8; probe.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, probe);
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_proxy_protocol = 0;

    let peer: SocketAddr = "198.51.100.44:55221".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

    let (client_reader, _client_writer) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(2048);

    let beobachten = BeobachtenStore::new();
    handle_bad_client(
        client_reader,
        client_visible_writer,
        &probe,
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    let mut observed = vec![0u8; backend_reply.len()];
    client_visible_reader.read_exact(&mut observed).await.unwrap();
    assert_eq!(observed, backend_reply);
    assert!(observed.starts_with(b"HTTP/"));
    accept_task.await.unwrap();
}

#[tokio::test]
async fn backend_unavailable_falls_back_to_silent_consume() {
    let temp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unused_port = temp_listener.local_addr().unwrap().port();
    drop(temp_listener);

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = unused_port;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_proxy_protocol = 0;

    let peer: SocketAddr = "203.0.113.11:42425".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let probe = b"GET /probe HTTP/1.1\r\nHost: x\r\n\r\n";

    let (mut client_reader_side, client_reader) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(256);
    let beobachten = BeobachtenStore::new();

    let task = tokio::spawn(async move {
        handle_bad_client(
            client_reader,
            client_visible_writer,
            probe,
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;
    });

    client_reader_side.write_all(b"noise").await.unwrap();
    drop(client_reader_side);

    timeout(Duration::from_secs(3), task).await.unwrap().unwrap();

    let mut buf = [0u8; 1];
    let n = timeout(Duration::from_secs(1), client_visible_reader.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn mask_disabled_consumes_client_data_without_response() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = false;

    let peer: SocketAddr = "198.51.100.12:45454".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let initial = b"scanner";

    let (mut client_reader_side, client_reader) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(256);
    let beobachten = BeobachtenStore::new();

    let task = tokio::spawn(async move {
        handle_bad_client(
            client_reader,
            client_visible_writer,
            initial,
            peer,
            local_addr,
            &config,
            &beobachten,
        )
        .await;
    });

    client_reader_side.write_all(b"untrusted payload").await.unwrap();
    drop(client_reader_side);

    timeout(Duration::from_secs(3), task).await.unwrap().unwrap();

    let mut buf = [0u8; 1];
    let n = timeout(Duration::from_secs(1), client_visible_reader.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn proxy_protocol_v1_header_is_sent_before_probe() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let probe = b"GET / HTTP/1.1\r\nHost: front.example\r\n\r\n".to_vec();
    let backend_reply = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec();

    let accept_task = tokio::spawn({
        let probe = probe.clone();
        let backend_reply = backend_reply.clone();
        async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);

            let mut header_line = Vec::new();
            reader.read_until(b'\n', &mut header_line).await.unwrap();
            let header_text = String::from_utf8(header_line.clone()).unwrap();
            assert!(header_text.starts_with("PROXY TCP4 "));
            assert!(header_text.ends_with("\r\n"));

            let mut received_probe = vec![0u8; probe.len()];
            reader.read_exact(&mut received_probe).await.unwrap();
            assert_eq!(received_probe, probe);

            let mut stream = reader.into_inner();
            stream.write_all(&backend_reply).await.unwrap();
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_proxy_protocol = 1;

    let peer: SocketAddr = "203.0.113.15:50001".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

    let (client_reader, _client_writer) = duplex(256);
    let (mut client_visible_reader, client_visible_writer) = duplex(2048);

    let beobachten = BeobachtenStore::new();
    handle_bad_client(
        client_reader,
        client_visible_writer,
        &probe,
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    let mut observed = vec![0u8; backend_reply.len()];
    client_visible_reader.read_exact(&mut observed).await.unwrap();
    assert_eq!(observed, backend_reply);
    accept_task.await.unwrap();
}
