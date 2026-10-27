use std::io::{self, Cursor, Write};

use crate::crypto::{dencrypted_in_place, encrypt_in_place};
use crate::replay_protection::ReplayProtection;
use crate::token::ConnectToken;
use crate::{
    serialize::*, NetcodeError, NETCODE_CHALLENGE_TOKEN_BYTES, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, NETCODE_CONNECT_TOKEN_XNONCE_BYTES,
    NETCODE_KEY_BYTES, NETCODE_MAC_BYTES,
};
use crate::{NETCODE_USER_DATA_BYTES, NETCODE_VERSION_INFO};

#[derive(Debug)]
#[repr(u8)]
pub enum PacketType {
    ConnectionRequest = 0,
    ConnectionDenied = 1,
    Challenge = 2,
    Response = 3,
    KeepAlive = 4,
    Payload = 5,
    Disconnect = 6,
}

#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // TODO: Consider boxing types
pub enum Packet<'a> {
    ConnectionRequest {
        version_info: [u8; 13], // "NETCODE 1.02" ASCII with null terminator.
        protocol_id: u64,
        expire_timestamp: u64,
        xnonce: [u8; NETCODE_CONNECT_TOKEN_XNONCE_BYTES],
        data: [u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES],
    },
    ConnectionDenied,
    Challenge {
        token_sequence: u64,
        token_data: [u8; NETCODE_CHALLENGE_TOKEN_BYTES], // encrypted ChallengeToken
    },
    Response {
        token_sequence: u64,
        token_data: [u8; NETCODE_CHALLENGE_TOKEN_BYTES], // encrypted ChallengeToken
    },
    KeepAlive {
        client_index: u32,
        max_clients: u32,
    },
    Payload(&'a [u8]),
    Disconnect,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChallengeToken {
    pub client_id: u64,
    pub user_data: [u8; 256],
}

impl PacketType {
    fn from_u8(value: u8) -> Result<Self, NetcodeError> {
        use PacketType::*;

        let packet_type = match value {
            0 => ConnectionRequest,
            1 => ConnectionDenied,
            2 => Challenge,
            3 => Response,
            4 => KeepAlive,
            5 => Payload,
            6 => Disconnect,
            _ => return Err(NetcodeError::InvalidPacketType),
        };
        Ok(packet_type)
    }

    fn apply_replay_protection(&self) -> bool {
        use PacketType::*;

        matches!(self, KeepAlive | Payload | Disconnect)
    }
}

impl<'a> Packet<'a> {
    pub fn packet_type(&self) -> PacketType {
        match self {
            Packet::ConnectionRequest { .. } => PacketType::ConnectionRequest,
            Packet::ConnectionDenied => PacketType::ConnectionDenied,
            Packet::Challenge { .. } => PacketType::Challenge,
            Packet::Response { .. } => PacketType::Response,
            Packet::KeepAlive { .. } => PacketType::KeepAlive,
            Packet::Payload { .. } => PacketType::Payload,
            Packet::Disconnect => PacketType::Disconnect,
        }
    }

    pub fn id(&self) -> u8 {
        self.packet_type() as u8
    }

    pub fn connection_request_from_token(connect_token: &ConnectToken) -> Self {
        Packet::ConnectionRequest {
            xnonce: connect_token.xnonce,
            version_info: *NETCODE_VERSION_INFO,
            protocol_id: connect_token.protocol_id,
            expire_timestamp: connect_token.expire_timestamp,
            data: connect_token.private_data,
        }
    }

    pub fn generate_challenge(
        client_id: u64,
        user_data: &[u8; NETCODE_USER_DATA_BYTES],
        challenge_sequence: u64,
        challenge_key: &[u8; NETCODE_KEY_BYTES],
    ) -> Result<Self, NetcodeError> {
        let token = ChallengeToken::new(client_id, user_data);
        let mut buffer = [0u8; NETCODE_CHALLENGE_TOKEN_BYTES];
        token.write(&mut Cursor::new(&mut buffer[..]))?;
        encrypt_in_place(&mut buffer, challenge_sequence, challenge_key, b"")?;

        Ok(Packet::Challenge {
            token_sequence: challenge_sequence,
            token_data: buffer,
        })
    }

    fn write(&self, writer: &mut impl io::Write) -> Result<(), io::Error> {
        match self {
            Packet::ConnectionRequest {
                version_info,
                protocol_id,
                expire_timestamp,
                xnonce,
                data,
            } => {
                writer.write_all(version_info)?;
                writer.write_all(&protocol_id.to_le_bytes())?;
                writer.write_all(&expire_timestamp.to_le_bytes())?;
                writer.write_all(xnonce)?;
                writer.write_all(data)?;
            }
            Packet::Challenge {
                token_data,
                token_sequence,
            }
            | Packet::Response {
                token_data,
                token_sequence,
            } => {
                writer.write_all(&token_sequence.to_le_bytes())?;
                writer.write_all(token_data)?;
            }
            Packet::KeepAlive { max_clients, client_index } => {
                writer.write_all(&client_index.to_le_bytes())?;
                writer.write_all(&max_clients.to_le_bytes())?;
            }
            Packet::Payload(p) => {
                writer.write_all(p)?;
            }
            Packet::ConnectionDenied | Packet::Disconnect => {}
        }

        Ok(())
    }

    fn read(packet_type: PacketType, src: &'a [u8]) -> Result<Self, io::Error> {
        if matches!(packet_type, PacketType::Payload) {
            return Ok(Packet::Payload(src));
        }

        let src = &mut Cursor::new(src);

        match packet_type {
            PacketType::ConnectionRequest => {
                let version_info = read_bytes(src)?;
                let protocol_id = read_u64(src)?;
                let expire_timestamp = read_u64(src)?;
                let xnonce = read_bytes(src)?;
                let token_data = read_bytes(src)?;

                Ok(Packet::ConnectionRequest {
                    version_info,
                    protocol_id,
                    expire_timestamp,
                    xnonce,
                    data: token_data,
                })
            }
            PacketType::Challenge => {
                let token_sequence = read_u64(src)?;
                let token_data = read_bytes(src)?;

                Ok(Packet::Challenge {
                    token_data,
                    token_sequence,
                })
            }
            PacketType::Response => {
                let token_sequence = read_u64(src)?;
                let token_data = read_bytes(src)?;

                Ok(Packet::Response {
                    token_data,
                    token_sequence,
                })
            }
            PacketType::KeepAlive => {
                let client_index = read_u32(src)?;
                let max_clients = read_u32(src)?;

                Ok(Packet::KeepAlive { client_index, max_clients })
            }
            PacketType::ConnectionDenied => Ok(Packet::ConnectionDenied),
            PacketType::Disconnect => Ok(Packet::Disconnect),
            PacketType::Payload => unreachable!(),
        }
    }

    pub fn encode(&self, buffer: &mut [u8], protocol_id: u64, crypto_info: Option<(u64, &[u8; 32])>) -> Result<usize, NetcodeError> {
        if matches!(self, Packet::ConnectionRequest { .. }) {
            let mut writer = io::Cursor::new(buffer);
            let prefix_byte = encode_prefix(self.id(), 0);
            writer.write_all(&prefix_byte.to_le_bytes())?;

            self.write(&mut writer)?;
            Ok(writer.position() as usize)
        } else if let Some((sequence, private_key)) = crypto_info {
            let (start, end, aad) = {
                let mut writer = io::Cursor::new(&mut *buffer);
                let prefix_byte = {
                    let prefix_byte = encode_prefix(self.id(), sequence);
                    writer.write_all(&prefix_byte.to_le_bytes())?;
                    write_sequence(&mut writer, sequence)?;
                    prefix_byte
                };

                let start = writer.position() as usize;
                self.write(&mut writer)?;

                let additional_data = get_additional_data(prefix_byte, protocol_id);
                (start, writer.position() as usize, additional_data)
            };
            if buffer.len() < end + NETCODE_MAC_BYTES {
                return Err(NetcodeError::IoError(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "buffer too small to encode with encryption tag",
                )));
            }

            encrypt_in_place(&mut buffer[start..end + NETCODE_MAC_BYTES], sequence, private_key, &aad)?;
            Ok(end + NETCODE_MAC_BYTES)
        } else {
            Err(NetcodeError::UnavailablePrivateKey)
        }
    }

    pub fn decode(
        mut buffer: &'a mut [u8],
        protocol_id: u64,
        private_key: Option<&[u8; 32]>,
        replay_protection: Option<&mut ReplayProtection>,
    ) -> Result<(u64, Self), NetcodeError> {
        if buffer.is_empty() {
            return Err(NetcodeError::PacketTooSmall);
        }

        let prefix_byte = buffer[0];
        let (packet_type, sequence_len) = decode_prefix(prefix_byte);
        let packet_type = PacketType::from_u8(packet_type)?;

        if matches!(packet_type, PacketType::ConnectionRequest) {
            Ok((0, Packet::read(PacketType::ConnectionRequest, &buffer[1..])?))
        } else if let Some(private_key) = private_key {
            if sequence_len > 8 || buffer.len() < 1 + sequence_len + NETCODE_MAC_BYTES {
                return Err(NetcodeError::PacketTooSmall);
            }

            let (sequence, aad, read_pos) = {
                let src = &mut io::Cursor::new(&mut buffer);
                src.set_position(1);
                let sequence = read_sequence(src, sequence_len)?;
                let additional_data = get_additional_data(prefix_byte, protocol_id);
                (sequence, additional_data, src.position() as usize)
            };

            let apply_replay_protection = packet_type.apply_replay_protection();
            if let Some(ref replay_protection) = replay_protection {
                if apply_replay_protection && replay_protection.already_received(sequence) {
                    return Err(NetcodeError::DuplicatedSequence);
                }
            }

            dencrypted_in_place(&mut buffer[read_pos..], sequence, private_key, &aad)?;
            let packet = Packet::read(packet_type, &buffer[read_pos..buffer.len() - NETCODE_MAC_BYTES])?;

            if let Some(replay_protection) = replay_protection {
                if apply_replay_protection {
                    replay_protection.advance_sequence(sequence);
                }
            }

            Ok((sequence, packet))
        } else {
            Err(NetcodeError::UnavailablePrivateKey)
        }
    }
}

impl ChallengeToken {
    pub fn new(client_id: u64, user_data: &[u8; NETCODE_USER_DATA_BYTES]) -> Self {
        Self {
            client_id,
            user_data: *user_data,
        }
    }

    fn read(src: &mut impl io::Read) -> Result<Self, io::Error> {
        let client_id = read_u64(src)?;
        let user_data: [u8; NETCODE_USER_DATA_BYTES] = read_bytes(src)?;

        Ok(Self { client_id, user_data })
    }

    fn write(&self, out: &mut impl io::Write) -> Result<(), io::Error> {
        out.write_all(&self.client_id.to_le_bytes())?;
        out.write_all(&self.user_data)?;

        Ok(())
    }

    pub fn decode(
        token_data: [u8; NETCODE_CHALLENGE_TOKEN_BYTES],
        token_sequence: u64,
        challenge_key: &[u8; NETCODE_KEY_BYTES],
    ) -> Result<ChallengeToken, NetcodeError> {
        let mut decoded = [0u8; NETCODE_CHALLENGE_TOKEN_BYTES];
        decoded.copy_from_slice(&token_data);
        dencrypted_in_place(&mut decoded, token_sequence, challenge_key, b"")?;

        Ok(ChallengeToken::read(&mut Cursor::new(&mut decoded))?)
    }
}

fn get_additional_data(prefix: u8, protocol_id: u64) -> [u8; 13 + 8 + 1] {
    let mut buffer = [0; 13 + 8 + 1];
    buffer[..13].copy_from_slice(NETCODE_VERSION_INFO);
    buffer[13..21].copy_from_slice(&protocol_id.to_le_bytes());
    buffer[21] = prefix;

    buffer
}

fn decode_prefix(value: u8) -> (u8, usize) {
    ((value & 0xF), (value >> 4) as usize)
}

fn encode_prefix(value: u8, sequence: u64) -> u8 {
    value | ((sequence_bytes_required(sequence) as u8) << 4)
}

fn sequence_bytes_required(sequence: u64) -> usize {
    let mut mask: u64 = 0xFF00_0000_0000_0000;
    for i in 0..8 {
        if (sequence & mask) != 0x00 {
            return 8 - i;
        }

        mask >>= 8;
    }

    0
}

fn write_sequence(out: &mut impl io::Write, seq: u64) -> Result<usize, io::Error> {
    let len = sequence_bytes_required(seq);
    let sequence_scratch = seq.to_le_bytes();
    out.write(&sequence_scratch[..len])
}

fn read_sequence(source: &mut impl io::Read, len: usize) -> Result<u64, io::Error> {
    let mut seq_scratch = [0; 8];
    source.read_exact(&mut seq_scratch[0..len])?;
    Ok(u64::from_le_bytes(seq_scratch))
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::{crypto::generate_random_bytes, NETCODE_MAX_PACKET_BYTES, NETCODE_MAX_PAYLOAD_BYTES};

    use super::*;

    /// Sequence values at every prefix width boundary and at the top of the u64 domain.
    pub(crate) const CORPUS_SEQUENCES: [u64; 20] = [
        0,
        1,
        0xff,
        0x100,
        0xffff,
        0x1_0000,
        0xff_ffff,
        0x100_0000,
        0xffff_ffff,
        0x1_0000_0000,
        0xff_ffff_ffff,
        0x100_0000_0000,
        0xffff_ffff_ffff,
        0x1_0000_0000_0000,
        0xff_ffff_ffff_ffff,
        0x100_0000_0000_0000,
        u64::MAX - 256,
        u64::MAX - 255,
        u64::MAX - 1,
        u64::MAX,
    ];

    /// Deterministic datagrams of every length up to one byte above the maximum packet size,
    /// followed by every prefix byte at boundary lengths. Callers must copy before decoding.
    pub(crate) fn for_each_adversarial_datagram(mut check: impl FnMut(&[u8])) {
        for len in 0..=NETCODE_MAX_PACKET_BYTES + 1 {
            for salt in [0u8, 1, 0x55, 0xaa, 0xff] {
                let bytes: Vec<u8> = (0..len)
                    .map(|index| (index as u8).wrapping_mul(73).wrapping_add(len as u8).wrapping_add(salt))
                    .collect();
                check(&bytes);
            }
        }

        let boundary_lengths = (0..=32).chain([
            1078,
            NETCODE_MAX_PAYLOAD_BYTES,
            NETCODE_MAX_PACKET_BYTES,
            NETCODE_MAX_PACKET_BYTES + 1,
        ]);
        for len in boundary_lengths {
            for prefix in 0..=u8::MAX {
                let mut bytes: Vec<u8> = (0..len).map(|index| (index as u8).wrapping_mul(29).wrapping_add(prefix)).collect();
                if let Some(first) = bytes.first_mut() {
                    *first = prefix;
                }
                check(&bytes);
            }
        }
    }

    /// Every packet variant correctly encoded at every corpus sequence. The connection request is
    /// unencrypted and is emitted once with sequence zero.
    pub(crate) fn for_each_encoded_packet(protocol_id: u64, key: &[u8; NETCODE_KEY_BYTES], mut check: impl FnMut(u64, &Packet, &[u8])) {
        let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES];
        let request = Packet::ConnectionRequest {
            version_info: *NETCODE_VERSION_INFO,
            protocol_id,
            expire_timestamp: 30,
            xnonce: [33; NETCODE_CONNECT_TOKEN_XNONCE_BYTES],
            data: [66; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES],
        };
        let len = request.encode(&mut buffer, protocol_id, None).unwrap();
        check(0, &request, &buffer[..len]);

        for sequence in CORPUS_SEQUENCES {
            let packets = [
                Packet::ConnectionDenied,
                Packet::Challenge {
                    token_sequence: sequence,
                    token_data: [77; NETCODE_CHALLENGE_TOKEN_BYTES],
                },
                Packet::Response {
                    token_sequence: sequence,
                    token_data: [88; NETCODE_CHALLENGE_TOKEN_BYTES],
                },
                Packet::KeepAlive {
                    client_index: 3,
                    max_clients: 8,
                },
                Packet::Payload(&[]),
                Packet::Payload(&[42]),
                Packet::Disconnect,
            ];
            for packet in packets {
                let len = packet.encode(&mut buffer, protocol_id, Some((sequence, key))).unwrap();
                check(sequence, &packet, &buffer[..len]);
            }
        }
    }

    /// Encrypts an arbitrary plaintext body under a valid prefix, so the result authenticates
    /// even when the body is structurally invalid for its packet type.
    pub(crate) fn encrypt_raw_packet(
        packet_type: PacketType,
        sequence: u64,
        body: &[u8],
        protocol_id: u64,
        key: &[u8; NETCODE_KEY_BYTES],
    ) -> Vec<u8> {
        let prefix = encode_prefix(packet_type as u8, sequence);
        let mut packet = vec![prefix];
        write_sequence(&mut packet, sequence).unwrap();
        let start = packet.len();
        packet.extend_from_slice(body);
        packet.extend_from_slice(&[0; NETCODE_MAC_BYTES]);
        encrypt_in_place(&mut packet[start..], sequence, key, &get_additional_data(prefix, protocol_id)).unwrap();
        packet
    }

    #[test]
    fn connection_request_serialization() {
        let connection_request = Packet::ConnectionRequest {
            xnonce: generate_random_bytes(),
            version_info: [0; 13], // "NETCODE 1.02" ASCII with null terminator.
            protocol_id: 1,
            expire_timestamp: 3,
            data: [5; 1024],
        };
        let mut buffer = Vec::new();
        connection_request.write(&mut buffer).unwrap();
        let deserialized = Packet::read(PacketType::ConnectionRequest, &buffer).unwrap();

        assert_eq!(deserialized, connection_request);
    }

    #[test]
    fn connection_challenge_serialization() {
        let connection_challenge = Packet::Challenge {
            token_sequence: 0,
            token_data: [1u8; 300],
        };

        let mut buffer = Vec::new();
        connection_challenge.write(&mut buffer).unwrap();
        let deserialized = Packet::read(PacketType::Challenge, buffer.as_slice()).unwrap();

        assert_eq!(deserialized, connection_challenge);
    }

    #[test]
    fn connection_keep_alive_serialization() {
        let connection_keep_alive = Packet::KeepAlive {
            max_clients: 2,
            client_index: 1,
        };

        let mut buffer = Vec::new();
        connection_keep_alive.write(&mut buffer).unwrap();
        let deserialized = Packet::read(PacketType::KeepAlive, buffer.as_slice()).unwrap();

        assert_eq!(deserialized, connection_keep_alive);
    }

    #[test]
    fn prefix_sequence() {
        let packet_type = Packet::Disconnect.id();
        let sequence = 99999;

        let mut buffer = vec![];
        write_sequence(&mut buffer, sequence).unwrap();

        let prefix = encode_prefix(packet_type, sequence);
        let (d_packet_type, sequence_len) = decode_prefix(prefix);
        assert_eq!(packet_type, d_packet_type);
        assert_eq!(buffer.len(), sequence_len);

        let d_sequence = read_sequence(&mut buffer.as_slice(), sequence_len).unwrap();

        assert_eq!(sequence, d_sequence);
    }

    #[test]
    fn encrypt_decrypt_disconnect_packet() {
        let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES];
        let key = b"an example very very secret key."; // 32-bytes
        let packet = Packet::Disconnect;
        let protocol_id = 12;
        let sequence = 1;
        let len = packet.encode(&mut buffer, protocol_id, Some((sequence, key))).unwrap();
        let (d_sequence, d_packet) = Packet::decode(&mut buffer[..len], protocol_id, Some(key), None).unwrap();
        assert_eq!(sequence, d_sequence);
        assert_eq!(packet, d_packet);
    }

    #[test]
    fn encrypted_packet_strict_prefixes_do_not_advance_replay_protection() {
        let key = b"an example very very secret key.";
        let protocol_id = 12;

        for width in 0..=8 {
            let sequence = if width == 0 { 0 } else { 1u64 << ((width - 1) * 8) };
            let mut encoded = [0u8; NETCODE_MAX_PACKET_BYTES];
            let len = Packet::Payload(&[42])
                .encode(&mut encoded, protocol_id, Some((sequence, key)))
                .unwrap();
            assert_eq!(decode_prefix(encoded[0]).1, width);

            let mut replay = ReplayProtection::new();
            for prefix_len in 0..len {
                let mut prefix = encoded[..prefix_len].to_vec();
                assert!(
                    Packet::decode(&mut prefix, protocol_id, Some(key), Some(&mut replay)).is_err(),
                    "width {width}, prefix length {prefix_len}"
                );
                assert!(!replay.already_received(sequence));
            }

            let mut full = encoded[..len].to_vec();
            assert_eq!(
                Packet::decode(&mut full, protocol_id, Some(key), Some(&mut replay)).unwrap().0,
                sequence
            );
            assert!(replay.already_received(sequence));
        }
    }

    #[test]
    fn oversized_sequence_widths_and_short_mac_are_rejected() {
        let key = b"an example very very secret key.";
        let protocol_id = 12;
        let mut replay = ReplayProtection::new();

        for width in 9..=15 {
            let mut packet = vec![0; 1 + width + NETCODE_MAC_BYTES];
            packet[0] = (width as u8) << 4 | PacketType::Payload as u8;
            assert!(matches!(
                Packet::decode(&mut packet, protocol_id, Some(key), Some(&mut replay)),
                Err(NetcodeError::PacketTooSmall)
            ));
        }

        let sequence = u64::MAX;
        let mut encoded = [0u8; NETCODE_MAX_PACKET_BYTES];
        let len = Packet::Disconnect.encode(&mut encoded, protocol_id, Some((sequence, key))).unwrap();
        let mut short_mac = encoded[..len - 1].to_vec();
        assert!(matches!(
            Packet::decode(&mut short_mac, protocol_id, Some(key), Some(&mut replay)),
            Err(NetcodeError::PacketTooSmall)
        ));
        assert!(!replay.already_received(sequence));
    }

    #[test]
    fn max_sequence_authenticates_once() {
        let key = b"an example very very secret key.";
        let protocol_id = 12;
        let sequence = u64::MAX;
        let mut encoded = [0u8; NETCODE_MAX_PACKET_BYTES];
        let len = Packet::Payload(&[42])
            .encode(&mut encoded, protocol_id, Some((sequence, key)))
            .unwrap();
        let mut replay = ReplayProtection::new();

        let mut corrupt = encoded[..len].to_vec();
        corrupt[len - 1] ^= 1;
        assert!(matches!(
            Packet::decode(&mut corrupt, protocol_id, Some(key), Some(&mut replay)),
            Err(NetcodeError::CryptoError)
        ));
        assert!(!replay.already_received(sequence));

        let mut valid = encoded[..len].to_vec();
        assert_eq!(
            Packet::decode(&mut valid, protocol_id, Some(key), Some(&mut replay)).unwrap().0,
            sequence
        );
        assert!(replay.already_received(sequence));

        let mut duplicate = encoded[..len].to_vec();
        assert!(matches!(
            Packet::decode(&mut duplicate, protocol_id, Some(key), Some(&mut replay)),
            Err(NetcodeError::DuplicatedSequence)
        ));
    }

    #[test]
    fn adversarial_datagrams_only_consume_replay_for_authenticated_packets() {
        let key = b"an example very very secret key.";
        let protocol_id = 12;
        let mut low = ReplayProtection::new();
        for sequence in [0, 1, 2, 699, 700] {
            low.advance_sequence(sequence);
        }
        let mut top = ReplayProtection::new();
        for sequence in [u64::MAX - 255, u64::MAX - 1] {
            top.advance_sequence(sequence);
        }
        let windows = [ReplayProtection::new(), low, top];

        let mut case = 0;
        for_each_adversarial_datagram(|datagram| {
            case += 1;
            let first = datagram.first().copied();
            let context = format!("case {case}, length {}, prefix {first:?}", datagram.len());

            for window in &windows {
                let mut replay = window.clone();
                let before = format!("{replay:?}");
                let mut bytes = datagram.to_vec();
                match Packet::decode(&mut bytes, protocol_id, Some(key), Some(&mut replay)) {
                    Ok((sequence, packet)) if matches!(packet, Packet::KeepAlive { .. } | Packet::Payload(_) | Packet::Disconnect) => {
                        assert!(!window.already_received(sequence), "{context}");
                        assert!(replay.already_received(sequence), "{context}");
                    }
                    Ok((sequence, packet)) => {
                        if matches!(packet, Packet::ConnectionRequest { .. }) {
                            assert_eq!(sequence, 0, "{context}");
                        }
                        assert_eq!(before, format!("{replay:?}"), "{context}");
                    }
                    Err(error) => {
                        assert_eq!(before, format!("{replay:?}"), "{context}");
                        if let Some(first) = first {
                            let (packet_type, sequence_len) = decode_prefix(first);
                            if packet_type > PacketType::Disconnect as u8 {
                                assert!(matches!(error, NetcodeError::InvalidPacketType), "{context}: {error}");
                            } else if packet_type != PacketType::ConnectionRequest as u8 && sequence_len > 8 {
                                assert!(matches!(error, NetcodeError::PacketTooSmall), "{context}: {error}");
                            }
                        } else {
                            assert!(matches!(error, NetcodeError::PacketTooSmall), "{context}: {error}");
                        }
                    }
                }
            }

            let mut bytes = datagram.to_vec();
            if let Ok((sequence, packet)) = Packet::decode(&mut bytes, protocol_id, None, None) {
                assert!(matches!(packet, Packet::ConnectionRequest { .. }), "{context}");
                assert_eq!(sequence, 0, "{context}");
            }
        });
    }

    #[test]
    fn encoded_packet_corpus_round_trips_and_rejects_truncation_and_corruption() {
        let key = b"an example very very secret key.";
        let wrong_key = &[0x5a; NETCODE_KEY_BYTES];
        let protocol_id = 12;

        for_each_encoded_packet(protocol_id, key, |sequence, packet, encoded| {
            let context = format!("{packet:?} at sequence {sequence}");
            let protected = match packet {
                Packet::KeepAlive { .. } | Packet::Payload(_) | Packet::Disconnect => true,
                Packet::ConnectionRequest { .. } | Packet::ConnectionDenied | Packet::Challenge { .. } | Packet::Response { .. } => false,
            };
            let request = matches!(packet, Packet::ConnectionRequest { .. });

            let mut replay = ReplayProtection::new();
            let mut full = encoded.to_vec();
            let (decoded_sequence, decoded) = Packet::decode(&mut full, protocol_id, Some(key), Some(&mut replay)).unwrap();
            assert_eq!(decoded_sequence, sequence, "{context}");
            assert_eq!(&decoded, packet, "{context}");
            assert_eq!(replay.already_received(sequence), protected, "{context}");
            if protected {
                let mut duplicate = encoded.to_vec();
                assert!(
                    matches!(
                        Packet::decode(&mut duplicate, protocol_id, Some(key), Some(&mut replay)),
                        Err(NetcodeError::DuplicatedSequence)
                    ),
                    "{context}"
                );
            }

            let empty = format!("{:?}", ReplayProtection::new());
            let rejected = |bytes: &mut [u8], case: &str| {
                let mut replay = ReplayProtection::new();
                assert!(
                    Packet::decode(bytes, protocol_id, Some(key), Some(&mut replay)).is_err(),
                    "{context}: {case}"
                );
                assert_eq!(empty, format!("{replay:?}"), "{context}: {case}");
            };

            for prefix_len in 0..encoded.len() {
                rejected(&mut encoded[..prefix_len].to_vec(), &format!("prefix length {prefix_len}"));
            }

            if request {
                let mut keyless = encoded.to_vec();
                assert!(matches!(
                    Packet::decode(&mut keyless, protocol_id, None, None),
                    Ok((0, Packet::ConnectionRequest { .. }))
                ));
                return;
            }

            for index in 0..encoded.len() {
                let mut corrupt = encoded.to_vec();
                corrupt[index] ^= 0x01;
                rejected(&mut corrupt, &format!("bit flip at {index}"));
                let mut corrupt = encoded.to_vec();
                corrupt[index] ^= 0x80;
                rejected(&mut corrupt, &format!("high bit flip at {index}"));
            }

            let mut replay = ReplayProtection::new();
            assert!(
                matches!(
                    Packet::decode(&mut encoded.to_vec(), protocol_id, Some(wrong_key), Some(&mut replay)),
                    Err(NetcodeError::CryptoError)
                ),
                "{context}: wrong key"
            );
            assert!(
                matches!(
                    Packet::decode(&mut encoded.to_vec(), protocol_id + 1, Some(key), Some(&mut replay)),
                    Err(NetcodeError::CryptoError)
                ),
                "{context}: wrong protocol"
            );
            assert!(
                matches!(
                    Packet::decode(&mut encoded.to_vec(), protocol_id, None, Some(&mut replay)),
                    Err(NetcodeError::UnavailablePrivateKey)
                ),
                "{context}: keyless"
            );
            assert_eq!(empty, format!("{replay:?}"), "{context}");
        });
    }

    #[test]
    fn authenticated_short_bodies_fail_without_consuming_replay() {
        let key = b"an example very very secret key.";
        let protocol_id = 12;

        for sequence in [700, u64::MAX] {
            let mut populated = ReplayProtection::new();
            for received in [sequence - 255, sequence - 1] {
                populated.advance_sequence(received);
            }

            for window in [ReplayProtection::new(), populated] {
                for body_len in 0..8 {
                    let mut replay = window.clone();
                    let before = format!("{replay:?}");
                    let mut short = encrypt_raw_packet(PacketType::KeepAlive, sequence, &[0; 8][..body_len], protocol_id, key);
                    assert!(
                        matches!(
                            Packet::decode(&mut short, protocol_id, Some(key), Some(&mut replay)),
                            Err(NetcodeError::IoError(_))
                        ),
                        "sequence {sequence}, body length {body_len}"
                    );
                    assert_eq!(before, format!("{replay:?}"), "sequence {sequence}, body length {body_len}");

                    let mut valid = [0; NETCODE_MAX_PACKET_BYTES];
                    let len = Packet::Payload(&[42])
                        .encode(&mut valid, protocol_id, Some((sequence, key)))
                        .unwrap();
                    let mut duplicate = valid[..len].to_vec();
                    assert_eq!(
                        Packet::decode(&mut valid[..len], protocol_id, Some(key), Some(&mut replay)).unwrap(),
                        (sequence, Packet::Payload(&[42]))
                    );
                    assert!(matches!(
                        Packet::decode(&mut duplicate, protocol_id, Some(key), Some(&mut replay)),
                        Err(NetcodeError::DuplicatedSequence)
                    ));
                    for received in [sequence - 255, sequence - 1] {
                        assert_eq!(replay.already_received(received), window.already_received(received));
                    }
                }
            }
        }

        for packet_type in [PacketType::Challenge as u8, PacketType::Response as u8] {
            for body_len in 0..8 + NETCODE_CHALLENGE_TOKEN_BYTES {
                let mut replay = ReplayProtection::new();
                let before = format!("{replay:?}");
                let mut short = encrypt_raw_packet(PacketType::from_u8(packet_type).unwrap(), 9, &vec![0; body_len], protocol_id, key);
                assert!(
                    matches!(
                        Packet::decode(&mut short, protocol_id, Some(key), Some(&mut replay)),
                        Err(NetcodeError::IoError(_))
                    ),
                    "body length {body_len}"
                );
                assert_eq!(before, format!("{replay:?}"));
            }
        }
    }

    #[test]
    fn encrypt_decrypt_denied_packet() {
        let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES];
        let key = b"an example very very secret key."; // 32-bytes
        let packet = Packet::ConnectionDenied;
        let protocol_id = 12;
        let sequence = 2;
        let len = packet.encode(&mut buffer, protocol_id, Some((sequence, key))).unwrap();
        let (d_sequence, d_packet) = Packet::decode(&mut buffer[..len], protocol_id, Some(key), None).unwrap();
        assert_eq!(sequence, d_sequence);
        assert_eq!(packet, d_packet);
    }

    #[test]
    fn encrypt_decrypt_payload_packet() {
        let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES];
        let payload = vec![7u8; NETCODE_MAX_PAYLOAD_BYTES];
        let key = b"an example very very secret key."; // 32-bytes
        let packet = Packet::Payload(&payload);
        let protocol_id = 12;
        let sequence = 2;
        let len = packet.encode(&mut buffer, protocol_id, Some((sequence, key))).unwrap();
        let (d_sequence, d_packet) = Packet::decode(&mut buffer[..len], protocol_id, Some(key), None).unwrap();
        assert_eq!(sequence, d_sequence);
        match d_packet {
            Packet::Payload(ref p) => assert_eq!(&payload, p),
            _ => unreachable!(),
        }
        assert_eq!(packet, d_packet);
    }

    #[test]
    fn encrypt_decrypt_challenge_token() {
        let client_id = 0;
        let user_data = generate_random_bytes();
        let challenge_key = generate_random_bytes();
        let challenge_sequence = 1;
        let token = ChallengeToken::new(client_id, &user_data);
        let packet = Packet::generate_challenge(client_id, &user_data, challenge_sequence, &challenge_key).unwrap();

        match packet {
            Packet::Challenge {
                token_data,
                token_sequence,
            } => {
                let decoded = ChallengeToken::decode(token_data, token_sequence, &challenge_key).unwrap();
                assert_eq!(decoded, token);
            }
            _ => unreachable!(),
        }
    }
}
