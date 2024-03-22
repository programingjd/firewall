use read_until_slice::AsyncBufReadUntilSliceExt;
use std::str::from_utf8;
use tokio::io::BufStream;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

pub async fn content_length(
    stream: &mut BufStream<TlsStream<TcpStream>>,
    buf: &mut Vec<u8>,
) -> Option<usize> {
    stream.read_until_slice(b"\r\n\r\n", buf).await.ok()?;
    assert!(buf.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(buf.ends_with(b"\r\n\r\n"));
    let indices = buf
        .windows(2)
        .enumerate()
        .filter_map(|it| if it.1 == b"\r\n" { Some(it.0) } else { None })
        .collect::<Vec<_>>();
    indices.windows(2).find_map(|it| {
        let mut split = buf[it[0] + 2..it[1]].split(|&it| it == b':');
        if let Some(key) = split.next() {
            if key.eq_ignore_ascii_case(b"content-length") {
                split
                    .next()
                    .and_then(|it| from_utf8(it).ok())
                    .and_then(|it| it.trim().parse::<usize>().ok())
            } else {
                None
            }
        } else {
            None
        }
    })
}
