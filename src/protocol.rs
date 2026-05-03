//! Wire-compatible encoder/decoder for the rathole control protocol (v1).
//!
//! Rathole serializes its types with `bincode` 1.x default options:
//! fixed-int little-endian, `u32` enum tags, no length-prefix variation.
//! This module hand-encodes the same on-wire representation so we can avoid
//! pulling in `serde` + `bincode` for a handful of fixed-size frames.
//!
//! # Frames produced/consumed by this client
//! | Type             | Bytes | Layout                                |
//! |------------------|------:|---------------------------------------|
//! | `Hello`          | 37    | tag(u32 LE) + version(u8) + 32B digest|
//! | `Auth`           | 32    | 32B digest                            |
//! | `Ack`            | 4     | tag(u32 LE)                           |
//! | `ControlCmd`     | 4     | tag(u32 LE)                           |
//! | `DataCmd`        | 4     | tag(u32 LE)                           |
//!
//! See <https://github.com/rathole-org/rathole/blob/main/src/protocol.rs>
//! for the upstream definitions.

use crate::error::{Error, Result};
use sha2::{Digest as Sha256Trait, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTO_V1: u8 = 1;
pub const HASH_LEN: usize = 32;

pub const HELLO_LEN: usize = 4 + 1 + HASH_LEN; // 37
#[allow(dead_code)]
pub const AUTH_LEN: usize = HASH_LEN; // 32
pub const ACK_LEN: usize = 4;
pub const CMD_LEN: usize = 4;

/// 32-byte SHA-256 output used for service identifiers, nonces and session keys.
pub type Digest = [u8; HASH_LEN];

/// Discriminant of the `Hello` enum on the wire.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloKind {
    Control = 0,
    Data = 1,
}

/// Server `Ack` reply on the control channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ack {
    Ok = 0,
    ServiceNotExist = 1,
    AuthFailed = 2,
}

/// Commands sent by the server on the control channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlCmd {
    CreateDataChannel = 0,
    HeartBeat = 1,
}

/// Commands the server sends at the start of each data channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataCmd {
    StartForwardTcp = 0,
    StartForwardUdp = 1,
    #[allow(dead_code)]
    StartForwardSocketStream = 2,
}

/// SHA-256 digest of an arbitrary byte slice.
pub fn digest(data: &[u8]) -> Digest {
    Sha256::digest(data).into()
}

/// `session_key = sha256(token || nonce)`. Mirrors rathole's derivation.
pub fn session_key(token: &str, nonce: &Digest) -> Digest {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.update(nonce);
    h.finalize().into()
}

/// Encode a `Hello` frame to its 37-byte representation.
pub fn encode_hello(kind: HelloKind, version: u8, d: &Digest) -> [u8; HELLO_LEN] {
    let mut buf = [0u8; HELLO_LEN];
    buf[..4].copy_from_slice(&(kind as u32).to_le_bytes());
    buf[4] = version;
    buf[5..].copy_from_slice(d);
    buf
}

/// Read and decode a `Hello` frame from `r`.
pub async fn read_hello<R: AsyncRead + Unpin>(r: &mut R) -> Result<(HelloKind, u8, Digest)> {
    let mut buf = [0u8; HELLO_LEN];
    r.read_exact(&mut buf).await?;
    let tag = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let kind = match tag {
        0 => HelloKind::Control,
        1 => HelloKind::Data,
        _ => return Err(Error::Protocol("invalid Hello tag")),
    };
    let version = buf[4];
    let mut d = [0u8; HASH_LEN];
    d.copy_from_slice(&buf[5..]);
    Ok((kind, version, d))
}

/// Write the 32-byte `Auth` frame.
pub async fn write_auth<W: AsyncWrite + Unpin>(w: &mut W, key: &Digest) -> Result<()> {
    w.write_all(key).await?;
    w.flush().await?;
    Ok(())
}

/// Read the 4-byte `Ack` reply.
pub async fn read_ack<R: AsyncRead + Unpin>(r: &mut R) -> Result<Ack> {
    let mut buf = [0u8; ACK_LEN];
    r.read_exact(&mut buf).await?;
    let tag = u32::from_le_bytes(buf);
    match tag {
        0 => Ok(Ack::Ok),
        1 => Ok(Ack::ServiceNotExist),
        2 => Ok(Ack::AuthFailed),
        _ => Err(Error::Protocol("invalid Ack tag")),
    }
}

/// Read a 4-byte `ControlChannelCmd` from the server.
pub async fn read_control_cmd<R: AsyncRead + Unpin>(r: &mut R) -> Result<ControlCmd> {
    let mut buf = [0u8; CMD_LEN];
    r.read_exact(&mut buf).await?;
    let tag = u32::from_le_bytes(buf);
    match tag {
        0 => Ok(ControlCmd::CreateDataChannel),
        1 => Ok(ControlCmd::HeartBeat),
        _ => Err(Error::Protocol("invalid ControlChannelCmd tag")),
    }
}

/// Read a 4-byte `DataChannelCmd` from the server (sent once per data channel).
pub async fn read_data_cmd<R: AsyncRead + Unpin>(r: &mut R) -> Result<DataCmd> {
    let mut buf = [0u8; CMD_LEN];
    r.read_exact(&mut buf).await?;
    let tag = u32::from_le_bytes(buf);
    match tag {
        0 => Ok(DataCmd::StartForwardTcp),
        1 => Ok(DataCmd::StartForwardUdp),
        2 => Ok(DataCmd::StartForwardSocketStream),
        _ => Err(Error::Protocol("invalid DataChannelCmd tag")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_lengths_match_rathole() {
        assert_eq!(HELLO_LEN, 37);
        assert_eq!(AUTH_LEN, 32);
        assert_eq!(ACK_LEN, 4);
        assert_eq!(CMD_LEN, 4);
    }

    #[test]
    fn hello_encoding_roundtrip() {
        let d = [7u8; HASH_LEN];
        let buf = encode_hello(HelloKind::Control, PROTO_V1, &d);
        assert_eq!(buf[..4], [0, 0, 0, 0]);
        assert_eq!(buf[4], PROTO_V1);
        assert_eq!(&buf[5..], &d);

        let buf = encode_hello(HelloKind::Data, PROTO_V1, &d);
        assert_eq!(buf[..4], [1, 0, 0, 0]);
    }

    #[test]
    fn session_key_matches_rathole_derivation() {
        let nonce = [9u8; HASH_LEN];
        let key = session_key("hello", &nonce);
        // sha256("hello" || nonce-of-9s)
        let mut h = Sha256::new();
        h.update(b"hello");
        h.update(&nonce);
        let expect: [u8; HASH_LEN] = h.finalize().into();
        assert_eq!(key, expect);
    }

    #[tokio::test]
    async fn read_ack_decodes_all_variants() {
        for (bytes, want) in [
            ([0u8, 0, 0, 0], Ack::Ok),
            ([1, 0, 0, 0], Ack::ServiceNotExist),
            ([2, 0, 0, 0], Ack::AuthFailed),
        ] {
            let mut cur = &bytes[..];
            assert_eq!(read_ack(&mut cur).await.unwrap(), want);
        }
    }
}
