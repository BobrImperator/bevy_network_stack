use std::{error::Error, fmt, net::SocketAddr, time::Duration};

use crate::{
    packet::Packet,
    replay_protection::ReplayProtection,
    token::{ConnectToken, TokenGenerationError},
    NetcodeError, NETCODE_CHALLENGE_TOKEN_BYTES, NETCODE_KEY_BYTES, NETCODE_MAX_PACKET_BYTES, NETCODE_MAX_PAYLOAD_BYTES, NETCODE_SEND_RATE,
    NETCODE_USER_DATA_BYTES,
};

/// The reason why a client is in error state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    ConnectTokenExpired,
    ConnectionTimedOut,
    ConnectionResponseTimedOut,
    ConnectionRequestTimedOut,
    ConnectionDenied,
    DisconnectedByClient,
    DisconnectedByServer,
}

#[derive(Debug, PartialEq, Eq)]
enum ClientState {
    Disconnected(DisconnectReason),
    SendingConnectionRequest,
    SendingConnectionResponse,
    Connected,
}

/// Configuration to establish a secure or unsecure connection with the server.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ClientAuthentication {
    /// Establishes a safe connection with the server using the [crate::ConnectToken].
    ///
    /// See also [crate::ServerAuthentication::Secure]
    Secure { connect_token: ConnectToken },
    /// Establishes an unsafe connection with the server, useful for testing and prototyping.
    ///
    /// See also [crate::ServerAuthentication::Unsecure]
    Unsecure {
        protocol_id: u64,
        client_id: u64,
        server_addr: SocketAddr,
        user_data: Option<[u8; NETCODE_USER_DATA_BYTES]>,
    },
}

/// A client that can generate encrypted packets that be sent to the connected server, or consume
/// encrypted packets from the server.
/// The client is agnostic from the transport layer, only consuming and generating bytes
/// that can be transported in any way desired.
#[derive(Debug)]
pub struct NetcodeClient {
    state: ClientState,
    client_id: u64,
    connect_start_time: Duration,
    last_packet_send_time: Option<Duration>,
    last_packet_received_time: Duration,
    current_time: Duration,
    sequence: u64,
    server_addr: SocketAddr,
    server_addr_index: usize,
    connect_token: ConnectToken,
    challenge_token_sequence: u64,
    challenge_token_data: [u8; NETCODE_CHALLENGE_TOKEN_BYTES],
    max_clients: u32,
    client_index: u32,
    send_rate: Duration,
    replay_protection: ReplayProtection,
    out: [u8; NETCODE_MAX_PACKET_BYTES],
}

impl fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DisconnectReason::*;

        match *self {
            ConnectTokenExpired => write!(f, "connection token has expired"),
            ConnectionTimedOut => write!(f, "connection timed out"),
            ConnectionResponseTimedOut => write!(f, "connection timed out during response step"),
            ConnectionRequestTimedOut => write!(f, "connection timed out during request step"),
            ConnectionDenied => write!(f, "server denied connection"),
            DisconnectedByClient => write!(f, "connection terminated by client"),
            DisconnectedByServer => write!(f, "connection terminated by server"),
        }
    }
}

impl Error for DisconnectReason {}

impl NetcodeClient {
    pub fn new(current_time: Duration, authentication: ClientAuthentication) -> Result<Self, NetcodeError> {
        let connect_token: ConnectToken = match authentication {
            ClientAuthentication::Unsecure {
                server_addr,
                protocol_id,
                client_id,
                user_data,
            } => ConnectToken::generate(
                current_time,
                protocol_id,
                300,
                client_id,
                15,
                vec![server_addr],
                user_data.as_ref(),
                &[0; NETCODE_KEY_BYTES],
            )?,
            ClientAuthentication::Secure { connect_token } => connect_token,
        };

        let server_addr = connect_token.server_addresses[0].ok_or(TokenGenerationError::NoServerAddressAvailable)?;

        Ok(Self {
            sequence: 0,
            client_id: connect_token.client_id,
            server_addr,
            server_addr_index: 0,
            challenge_token_sequence: 0,
            state: ClientState::SendingConnectionRequest,
            connect_start_time: current_time,
            last_packet_send_time: None,
            last_packet_received_time: current_time,
            current_time,
            max_clients: 0,
            client_index: 0,
            send_rate: NETCODE_SEND_RATE,
            challenge_token_data: [0u8; NETCODE_CHALLENGE_TOKEN_BYTES],
            connect_token,
            replay_protection: ReplayProtection::new(),
            out: [0u8; NETCODE_MAX_PACKET_BYTES],
        })
    }

    pub fn is_connecting(&self) -> bool {
        matches!(
            self.state,
            ClientState::SendingConnectionRequest | ClientState::SendingConnectionResponse
        )
    }

    pub fn is_connected(&self) -> bool {
        self.state == ClientState::Connected
    }

    pub fn is_disconnected(&self) -> bool {
        matches!(self.state, ClientState::Disconnected(_))
    }

    pub fn current_time(&self) -> Duration {
        self.current_time
    }

    pub fn client_id(&self) -> u64 {
        self.client_id
    }

    /// Returns the duration since the client last received a packet.
    /// Useful to detect timeouts.
    pub fn time_since_last_received_packet(&self) -> Duration {
        self.current_time - self.last_packet_received_time
    }

    /// Returns the reason that the client was disconnected for.
    pub fn disconnect_reason(&self) -> Option<DisconnectReason> {
        if let ClientState::Disconnected(reason) = &self.state {
            return Some(*reason);
        }
        None
    }

    /// Returns the current server address the client is connected or trying to connect.
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Disconnect the client from the server.
    /// Returns a disconnect packet that should be sent to the server.
    pub fn disconnect(&mut self) -> Result<(SocketAddr, &mut [u8]), NetcodeError> {
        self.state = ClientState::Disconnected(DisconnectReason::DisconnectedByClient);
        let packet = Packet::Disconnect;
        let len = packet.encode(
            &mut self.out,
            self.connect_token.protocol_id,
            Some((self.sequence, &self.connect_token.client_to_server_key)),
        )?;

        Ok((self.server_addr, &mut self.out[..len]))
    }

    /// Process any packet received from the server. This function might return a payload sent from the
    /// server. If nothing is returned, it was a packet used for the internal protocol or an
    /// invalid packet.
    pub fn process_packet<'a>(&mut self, buffer: &'a mut [u8]) -> Option<&'a [u8]> {
        let packet = match Packet::decode(
            buffer,
            self.connect_token.protocol_id,
            Some(&self.connect_token.server_to_client_key),
            Some(&mut self.replay_protection),
        ) {
            Ok((_, packet)) => packet,
            Err(e) => {
                log::error!("Failed to decode packet: {}", e);
                return None;
            }
        };
        log::trace!("Received packet from server: {:?}", packet.packet_type());

        match (packet, &self.state) {
            (Packet::ConnectionDenied, ClientState::SendingConnectionRequest | ClientState::SendingConnectionResponse) => {
                self.state = ClientState::Disconnected(DisconnectReason::ConnectionDenied);
                self.last_packet_received_time = self.current_time;
            }
            (
                Packet::Challenge {
                    token_data,
                    token_sequence,
                },
                ClientState::SendingConnectionRequest,
            ) => {
                self.challenge_token_sequence = token_sequence;
                self.last_packet_received_time = self.current_time;
                self.last_packet_send_time = None;
                self.challenge_token_data = token_data;
                self.state = ClientState::SendingConnectionResponse;
            }
            (Packet::KeepAlive { .. }, ClientState::Connected) => {
                self.last_packet_received_time = self.current_time;
            }
            (Packet::KeepAlive { client_index, max_clients }, ClientState::SendingConnectionResponse) => {
                self.last_packet_received_time = self.current_time;
                self.max_clients = max_clients;
                self.client_index = client_index;
                self.state = ClientState::Connected;
            }
            (Packet::Payload(p), ClientState::Connected) => {
                self.last_packet_received_time = self.current_time;
                return Some(p);
            }
            (Packet::Disconnect, ClientState::Connected) => {
                self.state = ClientState::Disconnected(DisconnectReason::DisconnectedByServer);
                self.last_packet_received_time = self.current_time;
            }
            _ => {}
        }

        None
    }

    /// Returns the server address and an encrypted payload packet that can be sent to the server.
    pub fn generate_payload_packet(&mut self, payload: &[u8]) -> Result<(SocketAddr, &mut [u8]), NetcodeError> {
        if payload.len() > NETCODE_MAX_PAYLOAD_BYTES {
            return Err(NetcodeError::PayloadAboveLimit);
        }

        if self.state != ClientState::Connected {
            return Err(NetcodeError::ClientNotConnected);
        }

        let packet = Packet::Payload(payload);
        let len = packet.encode(
            &mut self.out,
            self.connect_token.protocol_id,
            Some((self.sequence, &self.connect_token.client_to_server_key)),
        )?;
        self.sequence += 1;
        self.last_packet_send_time = Some(self.current_time);

        Ok((self.server_addr, &mut self.out[..len]))
    }

    /// Update the internal state of the client, receives the duration since last updated.
    /// Might return the serve address and a protocol packet to be sent to the server.
    pub fn update(&mut self, duration: Duration) -> Option<(&mut [u8], SocketAddr)> {
        if let Err(e) = self.update_internal_state(duration) {
            log::error!("Failed to update client: {}", e);
            return None;
        }

        // Generate packet for the current state
        self.generate_packet()
    }

    fn update_internal_state(&mut self, duration: Duration) -> Result<(), NetcodeError> {
        self.current_time += duration;
        let connection_timed_out = self.connect_token.timeout_seconds > 0
            && (self.last_packet_received_time + Duration::from_secs(self.connect_token.timeout_seconds as u64) < self.current_time);

        match self.state {
            ClientState::SendingConnectionRequest | ClientState::SendingConnectionResponse => {
                let expire_seconds = self
                    .connect_token
                    .expire_timestamp
                    .saturating_sub(self.connect_token.create_timestamp);
                let connection_expired = (self.current_time - self.connect_start_time).as_secs() >= expire_seconds;
                if connection_expired {
                    self.state = ClientState::Disconnected(DisconnectReason::ConnectTokenExpired);
                    return Err(NetcodeError::Expired);
                }
                if connection_timed_out {
                    let reason = if self.state == ClientState::SendingConnectionResponse {
                        DisconnectReason::ConnectionResponseTimedOut
                    } else {
                        DisconnectReason::ConnectionRequestTimedOut
                    };
                    self.state = ClientState::Disconnected(reason);
                    // Try to connect to the next server address
                    self.server_addr_index += 1;
                    if self.server_addr_index >= 32 {
                        return Err(NetcodeError::NoMoreServers);
                    }
                    match self.connect_token.server_addresses[self.server_addr_index] {
                        None => return Err(NetcodeError::NoMoreServers),
                        Some(server_address) => {
                            self.state = ClientState::SendingConnectionRequest;
                            self.server_addr = server_address;
                            self.connect_start_time = self.current_time;
                            self.last_packet_send_time = None;
                            self.last_packet_received_time = self.current_time;
                            self.challenge_token_sequence = 0;

                            return Ok(());
                        }
                    }
                }
                Ok(())
            }
            ClientState::Connected => {
                if connection_timed_out {
                    self.state = ClientState::Disconnected(DisconnectReason::ConnectionTimedOut);
                    return Err(NetcodeError::Disconnected(DisconnectReason::ConnectionTimedOut));
                }

                Ok(())
            }
            ClientState::Disconnected(reason) => Err(NetcodeError::Disconnected(reason)),
        }
    }

    fn generate_packet(&mut self) -> Option<(&mut [u8], SocketAddr)> {
        if let Some(last_packet_send_time) = self.last_packet_send_time {
            if self.current_time - last_packet_send_time < self.send_rate {
                return None;
            }
        }

        if matches!(
            self.state,
            ClientState::Connected | ClientState::SendingConnectionRequest | ClientState::SendingConnectionResponse
        ) {
            self.last_packet_send_time = Some(self.current_time);
        }
        let packet = match self.state {
            ClientState::SendingConnectionRequest => Packet::connection_request_from_token(&self.connect_token),
            ClientState::SendingConnectionResponse => Packet::Response {
                token_sequence: self.challenge_token_sequence,
                token_data: self.challenge_token_data,
            },
            ClientState::Connected => Packet::KeepAlive {
                client_index: 0,
                max_clients: 0,
            },
            _ => return None,
        };

        let result = packet.encode(
            &mut self.out,
            self.connect_token.protocol_id,
            Some((self.sequence, &self.connect_token.client_to_server_key)),
        );
        match result {
            Err(_) => None,
            Ok(encoded) => {
                self.sequence += 1;
                Some((&mut self.out[..encoded], self.server_addr))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::generate_random_bytes,
        packet::{
            tests::{encrypt_raw_packet, for_each_adversarial_datagram, for_each_encoded_packet},
            PacketType,
        },
        token::{
            tests::{fixed_connect_token, fixed_private_token},
            TokenGenerationError,
        },
        NETCODE_MAC_BYTES, NETCODE_MAX_PACKET_BYTES,
    };

    use super::*;

    const FIXTURE_PROTOCOL_ID: u64 = 2;

    fn fixture_token(create_timestamp: u64, expire_timestamp: u64) -> ConnectToken {
        let private = fixed_private_token(4, &["127.0.0.1:5000".parse().unwrap()]);
        fixed_connect_token(
            &private,
            FIXTURE_PROTOCOL_ID,
            create_timestamp,
            expire_timestamp,
            &[1; NETCODE_KEY_BYTES],
        )
    }

    fn from_server(packet: &Packet, sequence: u64) -> Vec<u8> {
        let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES];
        let server_key = fixture_token(0, 30).server_to_client_key;
        let len = packet
            .encode(&mut buffer, FIXTURE_PROTOCOL_ID, Some((sequence, &server_key)))
            .unwrap();
        buffer[..len].to_vec()
    }

    /// A client driven into `state` without consuming sequence zero for a protected packet.
    fn fixture_client_in(state: &ClientState) -> NetcodeClient {
        let authentication = ClientAuthentication::Secure {
            connect_token: fixture_token(0, 30),
        };
        let mut client = NetcodeClient::new(Duration::ZERO, authentication).unwrap();
        client.update(Duration::ZERO).unwrap();
        if *state != ClientState::SendingConnectionRequest {
            let challenge = Packet::Challenge {
                token_sequence: 7,
                token_data: [9; NETCODE_CHALLENGE_TOKEN_BYTES],
            };
            client.process_packet(&mut from_server(&challenge, 0));
        }
        if matches!(state, ClientState::Connected | ClientState::Disconnected(_)) {
            let keep_alive = Packet::KeepAlive {
                client_index: 1,
                max_clients: 4,
            };
            client.process_packet(&mut from_server(&keep_alive, 1));
        }
        if matches!(state, ClientState::Disconnected(_)) {
            client.process_packet(&mut from_server(&Packet::Disconnect, 2));
        }
        assert_eq!(&client.state, state);
        client
    }

    fn fixture_states() -> [ClientState; 4] {
        [
            ClientState::SendingConnectionRequest,
            ClientState::SendingConnectionResponse,
            ClientState::Connected,
            ClientState::Disconnected(DisconnectReason::DisconnectedByServer),
        ]
    }

    fn receive_state(client: &NetcodeClient) -> String {
        format!(
            "{:?}",
            (
                &client.state,
                client.last_packet_received_time,
                &client.replay_protection,
                client.challenge_token_sequence,
                client.challenge_token_data,
                client.max_clients,
                client.client_index,
            )
        )
    }

    #[test]
    fn adversarial_datagrams_preserve_client_state() {
        for state in fixture_states() {
            let mut client = fixture_client_in(&state);
            client.update(Duration::from_secs(1));
            let before = receive_state(&client);
            let mut case = 0;
            for_each_adversarial_datagram(|datagram| {
                case += 1;
                let mut bytes = datagram.to_vec();
                assert_eq!(
                    client.process_packet(&mut bytes),
                    None,
                    "{state:?}, case {case}, length {}",
                    datagram.len()
                );
                assert_eq!(before, receive_state(&client), "{state:?}, case {case}, length {}", datagram.len());
            });
        }
    }

    #[test]
    fn truncated_and_corrupted_server_packets_preserve_client_state() {
        let server_key = fixture_token(0, 30).server_to_client_key;
        for state in fixture_states() {
            let mut client = fixture_client_in(&state);
            client.update(Duration::from_secs(1));
            let before = receive_state(&client);
            for_each_encoded_packet(FIXTURE_PROTOCOL_ID, &server_key, |sequence, packet, encoded| {
                let mut malformed: Vec<(String, Vec<u8>)> = (0..encoded.len())
                    .map(|len| (format!("prefix length {len}"), encoded[..len].to_vec()))
                    .collect();
                if !matches!(packet, Packet::ConnectionRequest { .. }) {
                    let body_end = encoded.len() - NETCODE_MAC_BYTES;
                    for index in (0..10.min(body_end)).chain([body_end - 1]).chain(body_end..encoded.len()) {
                        let mut corrupt = encoded.to_vec();
                        corrupt[index] ^= 0x01;
                        malformed.push((format!("bit flip at {index}"), corrupt));
                    }
                }
                for (case, mut bytes) in malformed {
                    assert_eq!(
                        client.process_packet(&mut bytes),
                        None,
                        "{state:?}, {packet:?} at {sequence}, {case}"
                    );
                    assert_eq!(before, receive_state(&client), "{state:?}, {packet:?} at {sequence}, {case}");
                }
            });
        }
    }

    #[test]
    fn authenticated_short_keep_alive_preserves_client_replay() {
        let server_key = fixture_token(0, 30).server_to_client_key;
        let mut client = fixture_client_in(&ClientState::Connected);
        let before = receive_state(&client);
        for body_len in 0..8 {
            let mut short = encrypt_raw_packet(PacketType::KeepAlive, 700, &[0; 8][..body_len], FIXTURE_PROTOCOL_ID, &server_key);
            assert_eq!(client.process_packet(&mut short), None);
            assert_eq!(before, receive_state(&client), "body length {body_len}");
        }

        let mut payload = from_server(&Packet::Payload(&[42]), 700);
        let mut duplicate = payload.clone();
        assert_eq!(client.process_packet(&mut payload), Some(&[42][..]));
        assert_eq!(client.process_packet(&mut duplicate), None);
    }

    #[test]
    fn sequence_zero_control_packets_change_client_state() {
        let disconnect = from_server(&Packet::Disconnect, 0);
        let denied = from_server(&Packet::ConnectionDenied, 0);
        assert_eq!(disconnect.len(), 1 + NETCODE_MAC_BYTES);
        assert_eq!(denied.len(), 1 + NETCODE_MAC_BYTES);

        let mut client = fixture_client_in(&ClientState::Connected);
        assert_eq!(client.process_packet(&mut disconnect.clone()), None);
        assert_eq!(client.disconnect_reason(), Some(DisconnectReason::DisconnectedByServer));

        for state in [ClientState::SendingConnectionRequest, ClientState::SendingConnectionResponse] {
            let mut client = fixture_client_in(&state);
            assert_eq!(client.process_packet(&mut denied.clone()), None);
            assert_eq!(client.disconnect_reason(), Some(DisconnectReason::ConnectionDenied), "{state:?}");
        }
    }

    #[test]
    fn client_requires_a_first_server_address() {
        let mut later_only = fixture_token(0, 30);
        later_only.server_addresses[0] = None;
        later_only.server_addresses[1] = Some("127.0.0.1:5000".parse().unwrap());

        for server_addresses in [[None; 32], later_only.server_addresses] {
            let mut connect_token = fixture_token(0, 30);
            connect_token.server_addresses = server_addresses;
            let result = NetcodeClient::new(Duration::ZERO, ClientAuthentication::Secure { connect_token });
            assert!(
                matches!(
                    result,
                    Err(NetcodeError::TokenGenerationError(TokenGenerationError::NoServerAddressAvailable))
                ),
                "{result:?}"
            );
        }
    }

    #[test]
    fn inverted_token_lifetime_expires_without_requesting() {
        for (create_timestamp, expire_timestamp, requests) in [(10, 9, false), (10, 10, false), (10, 11, true)] {
            let mut bytes = vec![];
            fixture_token(create_timestamp, expire_timestamp).write(&mut bytes).unwrap();
            let connect_token = ConnectToken::read(&mut bytes.as_slice()).unwrap();
            let mut client = NetcodeClient::new(Duration::ZERO, ClientAuthentication::Secure { connect_token }).unwrap();

            assert_eq!(
                client.update(Duration::ZERO).is_some(),
                requests,
                "{create_timestamp}..{expire_timestamp}"
            );
            let expected = if requests { None } else { Some(DisconnectReason::ConnectTokenExpired) };
            assert_eq!(client.disconnect_reason(), expected, "{create_timestamp}..{expire_timestamp}");
        }
    }

    #[test]
    fn client_connection() {
        let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES];
        let server_addresses: Vec<SocketAddr> = vec!["127.0.0.1:8080".parse().unwrap(), "127.0.0.2:3000".parse().unwrap()];
        let user_data = generate_random_bytes();
        let private_key = b"an example very very secret key."; // 32-bytes
        let protocol_id = 2;
        let expire_seconds = 3;
        let client_id = 4;
        let timeout_seconds = 5;
        let connect_token = ConnectToken::generate(
            Duration::ZERO,
            protocol_id,
            expire_seconds,
            client_id,
            timeout_seconds,
            server_addresses,
            Some(&user_data),
            private_key,
        )
        .unwrap();
        let server_key = connect_token.server_to_client_key;
        let client_key = connect_token.client_to_server_key;
        let authentication = ClientAuthentication::Secure { connect_token };
        let mut client = NetcodeClient::new(Duration::ZERO, authentication).unwrap();
        let (packet_buffer, _) = client.update(Duration::ZERO).unwrap();

        let (r_sequence, packet) = Packet::decode(packet_buffer, protocol_id, None, None).unwrap();
        assert_eq!(0, r_sequence);
        assert!(matches!(packet, Packet::ConnectionRequest { .. }));

        let challenge_sequence = 7;
        let user_data = generate_random_bytes();
        let challenge_key = generate_random_bytes();
        let challenge_packet = Packet::generate_challenge(client_id, &user_data, challenge_sequence, &challenge_key).unwrap();
        let len = challenge_packet.encode(&mut buffer, protocol_id, Some((0, &server_key))).unwrap();
        client.process_packet(&mut buffer[..len]);
        assert_eq!(ClientState::SendingConnectionResponse, client.state);

        let (packet_buffer, _) = client.update(Duration::ZERO).unwrap();
        let (_, packet) = Packet::decode(packet_buffer, protocol_id, Some(&client_key), None).unwrap();
        assert!(matches!(packet, Packet::Response { .. }));

        let max_clients = 4;
        let client_index = 2;
        let keep_alive_packet = Packet::KeepAlive { max_clients, client_index };
        let len = keep_alive_packet.encode(&mut buffer, protocol_id, Some((1, &server_key))).unwrap();
        client.process_packet(&mut buffer[..len]);

        assert_eq!(client.state, ClientState::Connected);

        let payload = vec![7u8; 500];
        let payload_packet = Packet::Payload(&payload[..]);
        let len = payload_packet.encode(&mut buffer, protocol_id, Some((2, &server_key))).unwrap();

        let payload_client = client.process_packet(&mut buffer[..len]).unwrap();
        assert_eq!(payload, payload_client);

        let to_send_payload = vec![5u8; 1000];
        let (_, packet) = client.generate_payload_packet(&to_send_payload).unwrap();
        let (_, result) = Packet::decode(packet, protocol_id, Some(&client_key), None).unwrap();
        match result {
            Packet::Payload(payload) => assert_eq!(to_send_payload, payload),
            _ => unreachable!(),
        }
    }
}
