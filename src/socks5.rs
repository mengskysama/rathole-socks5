//! Minimal SOCKS5 server-side handshake (RFC 1928 + RFC 1929).
//!
//! Supports:
//! - No-auth (method `0x00`) when no credentials are configured.
//! - Username/password auth (method `0x02`, RFC 1929) when credentials are
//!   configured; all other methods are rejected.
//!
//! Only the `CONNECT` command is implemented. UDP ASSOCIATE and BIND are not
//! supported.

use crate::error::{Error, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const VER_SOCKS5: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_OK: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Run the SOCKS5 handshake on `client`, then dial the requested target.
///
/// `auth` controls authentication:
/// - `None` — only `NO AUTH` (method `0x00`) is accepted.
/// - `Some((username, password))` — only `USERNAME/PASSWORD` (method `0x02`,
///   RFC 1929) is accepted; credentials are checked during sub-negotiation.
///
/// On success returns `(upstream, target)` where `target` is the address
/// string from the CONNECT request (e.g. `"example.com:443"`). The caller
/// bridges `client` ↔ upstream. On failure a SOCKS5 error reply is sent back
/// to `client` (best-effort) before the error is returned.
pub async fn accept<S>(client: &mut S, auth: Option<(&str, &str)>) -> Result<(TcpStream, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ---- Greeting --------------------------------------------------------
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != VER_SOCKS5 {
        return Err(Error::Socks5("unsupported SOCKS version"));
    }
    let nmethods = head[1] as usize;
    let mut methods = [0u8; 255];
    client.read_exact(&mut methods[..nmethods]).await?;

    match auth {
        None => {
            // Require no-auth.
            if !methods[..nmethods].contains(&METHOD_NO_AUTH) {
                let _ = client.write_all(&[VER_SOCKS5, METHOD_NO_ACCEPTABLE]).await;
                return Err(Error::Socks5("client did not offer NO AUTH method"));
            }
            client.write_all(&[VER_SOCKS5, METHOD_NO_AUTH]).await?;
        }
        Some((username, password)) => {
            // Require username/password.
            if !methods[..nmethods].contains(&METHOD_USERPASS) {
                let _ = client.write_all(&[VER_SOCKS5, METHOD_NO_ACCEPTABLE]).await;
                return Err(Error::Socks5("client did not offer USERNAME/PASSWORD method"));
            }
            client.write_all(&[VER_SOCKS5, METHOD_USERPASS]).await?;
            auth_userpass(client, username, password).await?;
        }
    }

    // ---- Request ---------------------------------------------------------
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != VER_SOCKS5 {
        return Err(Error::Socks5("bad request version"));
    }
    if req[1] != CMD_CONNECT {
        send_reply(client, REP_CMD_NOT_SUPPORTED).await?;
        return Err(Error::Socks5("only CONNECT is supported"));
    }
    let target = match req[3] {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            client.read_exact(&mut a).await?;
            let port = read_port(client).await?;
            format!("{}:{}", Ipv4Addr::from(a), port)
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            client.read_exact(&mut a).await?;
            let port = read_port(client).await?;
            format!("[{}]:{}", Ipv6Addr::from(a), port)
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            client.read_exact(&mut name).await?;
            let port = read_port(client).await?;
            let host = std::str::from_utf8(&name)
                .map_err(|_| Error::Socks5("non-utf8 domain name"))?;
            format!("{host}:{port}")
        }
        _ => {
            send_reply(client, REP_ATYP_NOT_SUPPORTED).await?;
            return Err(Error::Socks5("unsupported address type"));
        }
    };

    // ---- Connect upstream ------------------------------------------------
    match TcpStream::connect(&target).await {
        Ok(s) => {
            send_reply(client, REP_OK).await?;
            Ok((s, target))
        }
        Err(e) => {
            let rep = match e.kind() {
                std::io::ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
                std::io::ErrorKind::NetworkUnreachable
                | std::io::ErrorKind::AddrNotAvailable => REP_NETWORK_UNREACHABLE,
                std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::TimedOut => {
                    REP_HOST_UNREACHABLE
                }
                _ => REP_GENERAL_FAILURE,
            };
            let _ = send_reply(client, rep).await;
            Err(Error::Io(e))
        }
    }
}

/// RFC 1929 username/password sub-negotiation.
async fn auth_userpass<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut S,
    expected_user: &str,
    expected_pass: &str,
) -> Result<()> {
    // VER(1)=0x01  ULEN(1)  UNAME(ULEN)  PLEN(1)  PASSWD(PLEN)
    let mut ver = [0u8; 1];
    client.read_exact(&mut ver).await?;
    if ver[0] != 0x01 {
        return Err(Error::Socks5("bad username/password auth version"));
    }

    let mut ulen = [0u8; 1];
    client.read_exact(&mut ulen).await?;
    let mut uname = vec![0u8; ulen[0] as usize];
    client.read_exact(&mut uname).await?;

    let mut plen = [0u8; 1];
    client.read_exact(&mut plen).await?;
    let mut passwd = vec![0u8; plen[0] as usize];
    client.read_exact(&mut passwd).await?;

    let ok = uname == expected_user.as_bytes() && passwd == expected_pass.as_bytes();
    // Reply: VER(1)=0x01  STATUS(1)  — 0x00 = success
    client.write_all(&[0x01, if ok { 0x00 } else { 0x01 }]).await?;
    if ok {
        Ok(())
    } else {
        Err(Error::Socks5("invalid username or password"))
    }
}

async fn read_port<S: AsyncRead + Unpin>(client: &mut S) -> Result<u16> {
    let mut p = [0u8; 2];
    client.read_exact(&mut p).await?;
    Ok(u16::from_be_bytes(p))
}

/// Send a SOCKS5 reply with zeroed BND.ADDR/BND.PORT (0.0.0.0:0).
async fn send_reply<S: AsyncWrite + Unpin>(client: &mut S, rep: u8) -> Result<()> {
    let buf = [VER_SOCKS5, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    client.write_all(&buf).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn rejects_non_socks5() {
        let (mut a, mut b) = duplex(64);
        a.write_all(&[0x04, 0x01]).await.unwrap();
        let res = accept(&mut b, None).await;
        assert!(matches!(res, Err(Error::Socks5(_))));
    }

    #[tokio::test]
    async fn rejects_unsupported_method_no_auth() {
        let (mut a, mut b) = duplex(64);
        // client offers only user/pass; server requires no-auth
        a.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let res = accept(&mut b, None).await;
        assert!(matches!(res, Err(Error::Socks5(_))));
        let mut reply = [0u8; 2];
        a.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [VER_SOCKS5, METHOD_NO_ACCEPTABLE]);
    }

    #[tokio::test]
    async fn rejects_no_auth_when_credentials_required() {
        let (mut a, mut b) = duplex(64);
        // client offers only no-auth; server requires user/pass
        a.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let res = accept(&mut b, Some(("user", "pass"))).await;
        assert!(matches!(res, Err(Error::Socks5(_))));
        let mut reply = [0u8; 2];
        a.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [VER_SOCKS5, METHOD_NO_ACCEPTABLE]);
    }

    #[tokio::test]
    async fn rejects_wrong_credentials() {
        let (mut a, mut b) = duplex(256);
        // spawn accept first — otherwise read_exact on `a` deadlocks
        let h = tokio::spawn(async move { accept(&mut b, Some(("user", "pass"))).await });

        // greeting: offer user/pass
        a.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut greet = [0u8; 2];
        a.read_exact(&mut greet).await.unwrap();
        assert_eq!(greet, [0x05, METHOD_USERPASS]);

        // sub-negotiation: wrong password
        let user = b"user";
        let pass = b"wrong";
        let mut sub = vec![0x01, user.len() as u8];
        sub.extend_from_slice(user);
        sub.push(pass.len() as u8);
        sub.extend_from_slice(pass);
        a.write_all(&sub).await.unwrap();

        let mut sub_reply = [0u8; 2];
        a.read_exact(&mut sub_reply).await.unwrap();
        assert_eq!(sub_reply[0], 0x01);
        assert_ne!(sub_reply[1], 0x00); // failure

        assert!(matches!(h.await.unwrap(), Err(Error::Socks5(_))));
    }

    #[tokio::test]
    async fn full_connect_no_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { let _ = listener.accept().await; });

        let (mut visitor, mut server) = duplex(256);
        let h = tokio::spawn(async move { accept(&mut server, None).await });

        visitor.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greet = [0u8; 2];
        visitor.read_exact(&mut greet).await.unwrap();
        assert_eq!(greet, [0x05, 0x00]);

        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&port.to_be_bytes());
        visitor.write_all(&req).await.unwrap();

        let mut rep = [0u8; 10];
        visitor.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], REP_OK);
        let (_, target) = h.await.unwrap().unwrap();
        assert_eq!(target, format!("127.0.0.1:{port}"));
    }

    #[tokio::test]
    async fn full_connect_with_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { let _ = listener.accept().await; });

        let (mut visitor, mut server) = duplex(256);
        let h = tokio::spawn(async move { accept(&mut server, Some(("alice", "s3cr3t"))).await });

        // greeting: offer user/pass
        visitor.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut greet = [0u8; 2];
        visitor.read_exact(&mut greet).await.unwrap();
        assert_eq!(greet, [0x05, METHOD_USERPASS]);

        // sub-negotiation
        let user = b"alice";
        let pass = b"s3cr3t";
        let mut sub = vec![0x01, user.len() as u8];
        sub.extend_from_slice(user);
        sub.push(pass.len() as u8);
        sub.extend_from_slice(pass);
        visitor.write_all(&sub).await.unwrap();
        let mut sub_rep = [0u8; 2];
        visitor.read_exact(&mut sub_rep).await.unwrap();
        assert_eq!(sub_rep, [0x01, 0x00]);

        // CONNECT request
        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&port.to_be_bytes());
        visitor.write_all(&req).await.unwrap();

        let mut rep = [0u8; 10];
        visitor.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], REP_OK);
        let (_, target) = h.await.unwrap().unwrap();
        assert_eq!(target, format!("127.0.0.1:{port}"));
    }
}
