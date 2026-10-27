use std::{
    collections::{hash_map::Entry, HashMap},
    io,
    net::SocketAddr,
    time::Duration,
};

use crate::{
    crypto::generate_random_bytes,
    packet::{ChallengeToken, Packet},
    replay_protection::ReplayProtection,
    token::PrivateConnectToken,
    NetcodeError, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, NETCODE_CONNECT_TOKEN_XNONCE_BYTES, NETCODE_KEY_BYTES, NETCODE_MAC_BYTES,
    NETCODE_MAX_CLIENTS, NETCODE_MAX_PACKET_BYTES, NETCODE_MAX_PAYLOAD_BYTES, NETCODE_MAX_PENDING_CLIENTS, NETCODE_SEND_RATE,
    NETCODE_USER_DATA_BYTES, NETCODE_VERSION_INFO,
};

// Server packets sent before a client owns a slot use the upper half of the sequence space and
// per-connection packets use the lower half, so both never share a nonce under one client key.
const GLOBAL_SEQUENCE_START: u64 = 1 << 63;
const GLOBAL_SEQUENCE_END: u64 = u64::MAX;
const CONNECTION_SEQUENCE_END: u64 = GLOBAL_SEQUENCE_START - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Disconnected,
    PendingResponse,
    Connected,
}

#[derive(Debug, Clone)]
struct Connection {
    confirmed: bool,
    client_id: u64,
    state: ConnectionState,
    send_key: [u8; NETCODE_KEY_BYTES],
    receive_key: [u8; NETCODE_KEY_BYTES],
    user_data: [u8; NETCODE_USER_DATA_BYTES],
    addr: SocketAddr,
    last_packet_received_time: Duration,
    last_packet_send_time: Duration,
    timeout_seconds: i32,
    sequence: u64,
    expire_timestamp: u64,
    replay_protection: ReplayProtection,
    token_mac: [u8; NETCODE_MAC_BYTES],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectTokenState {
    Pending,
    Consumed,
}

/// A connect token admitted by the server, identified by its authenticated MAC. The entry is
/// retained until the token expires, so a consumed token cannot be admitted again.
#[derive(Debug, Copy, Clone)]
struct ConnectTokenEntry {
    address: SocketAddr,
    mac: [u8; NETCODE_MAC_BYTES],
    expire_timestamp: u64,
    state: ConnectTokenState,
}

impl ConnectTokenEntry {
    fn permits(&self, address: SocketAddr, now: u64) -> bool {
        self.state == ConnectTokenState::Pending && self.address == address && now < self.expire_timestamp
    }
}

/// A server that can generate packets from connect clients, that are encrypted, or process
/// incoming encrypted packets from clients. The server is agnostic from the transport layer, only
/// consuming and generating bytes that can be transported in any way desired.
#[derive(Debug)]
pub struct NetcodeServer {
    clients: Box<[Option<Connection>]>,
    pending_clients: HashMap<SocketAddr, Connection>,
    connect_token_entries: Box<[Option<ConnectTokenEntry>; NETCODE_MAX_CLIENTS * 2]>,
    protocol_id: u64,
    connect_key: [u8; NETCODE_KEY_BYTES],
    max_clients: usize,
    challenge_sequence: u64,
    challenge_key: [u8; NETCODE_KEY_BYTES],
    public_addresses: Vec<SocketAddr>,
    current_time: Duration,
    global_sequence: u64,
    minimum_connect_token_expire_timestamp: Option<Duration>,
    out: [u8; NETCODE_MAX_PACKET_BYTES],
}

/// Result from processing an packet in the server
#[derive(Debug, PartialEq, Eq)]
pub enum ServerResult<'a, 's> {
    /// Nothing needs to be done.
    None,
    /// A packet to be sent back to the processed address.
    PacketToSend { addr: SocketAddr, payload: &'s mut [u8] },
    /// A payload received from the client.
    Payload { client_id: u64, payload: &'a [u8] },
    /// A new client has connected
    ClientConnected {
        client_id: u64,
        addr: SocketAddr,
        user_data: Box<[u8; NETCODE_USER_DATA_BYTES]>,
        payload: &'s mut [u8],
    },
    /// The client connection has been terminated.
    ClientDisconnected {
        client_id: u64,
        addr: SocketAddr,
        payload: Option<&'s mut [u8]>,
    },
}

/// Configuration to establish a secure or unsecure connection with the server.
pub enum ServerAuthentication {
    /// Establishes a safe connection using a private key for encryption. The private key cannot be
    /// shared with the client. Connections are stablished using [crate::token::ConnectToken].
    ///
    /// Each token is admitted once, and the server remembers up to `NETCODE_MAX_CLIENTS * 2`
    /// distinct unexpired tokens, refusing new ones while that history is full.
    ///
    /// `max_connect_token_lifetime` is the longest lifetime the trusted issuer gives a token, a
    /// positive whole number of seconds measured on the same absolute clock as
    /// [ServerConfig::current_time]. A token is refused unless it expires at least that long after
    /// the server started, so a token issued before a restart cannot be replayed against the
    /// restarted server. Tokens issued during the server's first second may be refused too, and
    /// the client must retry with a newly issued token.
    ///
    /// See also [ClientAuthentication::Secure][crate::ClientAuthentication::Secure]
    Secure {
        private_key: [u8; NETCODE_KEY_BYTES],
        max_connect_token_lifetime: Duration,
    },
    /// Establishes unsafe connections with clients, useful for testing and prototyping.
    ///
    /// See also [ClientAuthentication::Unsecure][crate::ClientAuthentication::Unsecure]
    Unsecure,
}

pub struct ServerConfig {
    pub current_time: Duration,
    /// Maximum numbers of clients that can be connected at a time
    pub max_clients: usize,
    /// Unique identifier for this particular game/application.
    /// You can use a hash function with the current version of the game to generate this value
    /// so that older versions cannot connect to newer versions.
    pub protocol_id: u64,
    /// Publicly available addresses to which clients will attempt to connect.
    pub public_addresses: Vec<SocketAddr>,
    /// Authentication configuration for the server
    pub authentication: ServerAuthentication,
}

impl NetcodeServer {
    pub fn new(config: ServerConfig) -> Self {
        if config.max_clients > NETCODE_MAX_CLIENTS {
            // TODO: do we really need to set a max?
            //       only using for token entries
            panic!("The max clients allowed is {}", NETCODE_MAX_CLIENTS);
        }
        let challenge_key = generate_random_bytes();
        let clients = vec![None; config.max_clients].into_boxed_slice();

        let (connect_key, minimum_connect_token_expire_timestamp) = match config.authentication {
            ServerAuthentication::Unsecure => ([0; NETCODE_KEY_BYTES], None),
            ServerAuthentication::Secure {
                private_key,
                max_connect_token_lifetime,
            } => {
                assert!(
                    !max_connect_token_lifetime.is_zero() && max_connect_token_lifetime.subsec_nanos() == 0,
                    "maximum connect token lifetime must be a positive whole number of seconds"
                );
                let minimum = config
                    .current_time
                    .checked_add(max_connect_token_lifetime)
                    .filter(|minimum| *minimum <= Duration::from_secs(u64::MAX))
                    .expect("connect token startup cutoff exceeds the token timestamp range");
                (private_key, Some(minimum))
            }
        };

        Self {
            clients,
            connect_token_entries: Box::new([None; NETCODE_MAX_CLIENTS * 2]),
            pending_clients: HashMap::new(),
            protocol_id: config.protocol_id,
            connect_key,
            max_clients: config.max_clients,
            challenge_sequence: 0,
            global_sequence: GLOBAL_SEQUENCE_START,
            challenge_key,
            public_addresses: config.public_addresses,
            current_time: config.current_time,
            minimum_connect_token_expire_timestamp,
            out: [0u8; NETCODE_MAX_PACKET_BYTES],
        }
    }

    #[doc(hidden)]
    pub fn __test() -> Self {
        let config = ServerConfig {
            current_time: Duration::ZERO,
            max_clients: 32,
            protocol_id: 0,
            public_addresses: vec!["127.0.0.1:0".parse().unwrap()],
            authentication: ServerAuthentication::Unsecure,
        };
        Self::new(config)
    }

    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.public_addresses.clone()
    }

    pub fn current_time(&self) -> Duration {
        self.current_time
    }

    /// Admits a freshly authenticated token. A known token is admitted again only while it is
    /// pending at its original address and unexpired; a new token takes an empty or expired entry
    /// and is refused while every entry is live.
    fn find_or_add_connect_token_entry(&mut self, new_entry: ConnectTokenEntry) -> bool {
        let now = self.current_time.as_secs();
        if let Some(entry) = self.connect_token_entries.iter().flatten().find(|entry| entry.mac == new_entry.mac) {
            return entry.permits(new_entry.address, now);
        }

        let slot = self
            .connect_token_entries
            .iter_mut()
            .find(|slot| slot.is_none_or(|entry| entry.expire_timestamp <= now));
        let Some(slot) = slot else {
            return false;
        };
        *slot = Some(new_entry);
        true
    }

    fn connect_token_permits(&self, mac: &[u8; NETCODE_MAC_BYTES], address: SocketAddr) -> bool {
        let now = self.current_time.as_secs();
        self.connect_token_entries
            .iter()
            .flatten()
            .any(|entry| entry.mac == *mac && entry.permits(address, now))
    }

    /// Marks an eligible pending token consumed. A consumed token never becomes eligible again.
    fn consume_connect_token(&mut self, mac: &[u8; NETCODE_MAC_BYTES], address: SocketAddr) -> bool {
        let now = self.current_time.as_secs();
        match self.connect_token_entries.iter_mut().flatten().find(|entry| entry.mac == *mac) {
            Some(entry) if entry.permits(address, now) => {
                entry.state = ConnectTokenState::Consumed;
                true
            }
            _ => false,
        }
    }

    /// Returns the user data from the connected client.
    pub fn user_data(&self, client_id: u64) -> Option<[u8; NETCODE_USER_DATA_BYTES]> {
        if let Some(client) = find_client_by_id(&self.clients, client_id) {
            return Some(client.user_data);
        }

        None
    }

    /// Returns the duration since the connected client last received a packet.
    /// Useful to detect users that are timing out.
    pub fn time_since_last_received_packet(&self, client_id: u64) -> Option<Duration> {
        if let Some(client) = find_client_by_id(&self.clients, client_id) {
            let time = self.current_time - client.last_packet_received_time;
            return Some(time);
        }

        None
    }

    /// Returns the client address if connected.
    pub fn client_addr(&self, client_id: u64) -> Option<SocketAddr> {
        if let Some(client) = find_client_by_id(&self.clients, client_id) {
            return Some(client.addr);
        }

        None
    }

    fn handle_connection_request<'a>(
        &mut self,
        addr: SocketAddr,
        version_info: [u8; 13],
        protocol_id: u64,
        expire_timestamp: u64,
        xnonce: [u8; NETCODE_CONNECT_TOKEN_XNONCE_BYTES],
        data: [u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES],
    ) -> Result<ServerResult<'a, '_>, NetcodeError> {
        if version_info != *NETCODE_VERSION_INFO {
            return Err(NetcodeError::InvalidVersion);
        }

        if protocol_id != self.protocol_id {
            return Err(NetcodeError::InvalidProtocolID);
        }

        if self.current_time.as_secs() >= expire_timestamp {
            return Err(NetcodeError::Expired);
        }

        let connect_token = PrivateConnectToken::decode(&data, self.protocol_id, expire_timestamp, &xnonce, &self.connect_key)?;

        // Unsecure servers have neither a startup cutoff nor a host list check.
        if let Some(minimum) = self.minimum_connect_token_expire_timestamp {
            if Duration::from_secs(expire_timestamp) < minimum {
                return Err(NetcodeError::Expired);
            }

            let in_host_list = connect_token
                .server_addresses
                .iter()
                .filter_map(|host| *host)
                .any(|addr| self.public_addresses.contains(&addr));

            if !in_host_list {
                return Err(NetcodeError::NotInHostList);
            }
        }

        let addr_already_connected = find_client_mut_by_addr(&mut self.clients, addr).is_some();
        let id_already_connected = find_client_mut_by_id(&mut self.clients, connect_token.client_id).is_some();
        if id_already_connected || addr_already_connected {
            log::debug!(
                "Connection request denied: client {} already connected (address: {}).",
                connect_token.client_id,
                addr
            );
            return Ok(ServerResult::None);
        }

        if !self.pending_clients.contains_key(&addr) && self.pending_clients.len() >= NETCODE_MAX_PENDING_CLIENTS {
            log::warn!(
                "Connection request denied: reached max amount allowed of pending clients ({}).",
                NETCODE_MAX_PENDING_CLIENTS
            );
            return Ok(ServerResult::None);
        }

        let mut mac = [0u8; NETCODE_MAC_BYTES];
        mac.copy_from_slice(&data[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES..]);
        let connect_token_entry = ConnectTokenEntry {
            address: addr,
            mac,
            expire_timestamp,
            state: ConnectTokenState::Pending,
        };

        if !self.find_or_add_connect_token_entry(connect_token_entry) {
            log::warn!("Connection request denied: unable to add connect token entry");
            return Ok(ServerResult::None);
        }

        if self.clients.iter().flatten().count() >= self.max_clients {
            let sequence = allocate_sequence(&mut self.global_sequence, GLOBAL_SEQUENCE_END)?;
            self.pending_clients.remove(&addr);
            let packet = Packet::ConnectionDenied;
            let len = packet.encode(
                &mut self.out,
                self.protocol_id,
                Some((sequence, &connect_token.server_to_client_key)),
            )?;
            return Ok(ServerResult::PacketToSend {
                addr,
                payload: &mut self.out[..len],
            });
        }

        let sequence = allocate_sequence(&mut self.global_sequence, GLOBAL_SEQUENCE_END)?;
        self.challenge_sequence += 1;
        let packet = Packet::generate_challenge(
            connect_token.client_id,
            &connect_token.user_data,
            self.challenge_sequence,
            &self.challenge_key,
        )?;

        let len = packet.encode(
            &mut self.out,
            self.protocol_id,
            Some((sequence, &connect_token.server_to_client_key)),
        )?;

        log::trace!("Connection request from Client {}", connect_token.client_id);

        let replacement = Connection {
            confirmed: false,
            sequence: 0,
            client_id: connect_token.client_id,
            last_packet_received_time: self.current_time,
            last_packet_send_time: self.current_time,
            addr,
            state: ConnectionState::PendingResponse,
            send_key: connect_token.server_to_client_key,
            receive_key: connect_token.client_to_server_key,
            timeout_seconds: connect_token.timeout_seconds,
            expire_timestamp,
            user_data: connect_token.user_data,
            replay_protection: ReplayProtection::new(),
            token_mac: mac,
        };
        // A retransmitted token keeps its pending connection; a different token replaces all of it,
        // so the challenge just encrypted for that token is answered only under its own keys.
        let pending = match self.pending_clients.entry(addr) {
            Entry::Vacant(slot) => slot.insert(replacement),
            Entry::Occupied(mut slot) => {
                if slot.get().token_mac != mac {
                    slot.insert(replacement);
                }
                slot.into_mut()
            }
        };
        pending.last_packet_received_time = self.current_time;
        pending.last_packet_send_time = self.current_time;

        Ok(ServerResult::PacketToSend {
            addr,
            payload: &mut self.out[..len],
        })
    }

    /// Returns an encoded packet payload to be sent to the client
    pub fn generate_payload_packet<'s>(&'s mut self, client_id: u64, payload: &[u8]) -> Result<(SocketAddr, &'s mut [u8]), NetcodeError> {
        if payload.len() > NETCODE_MAX_PAYLOAD_BYTES {
            return Err(NetcodeError::PayloadAboveLimit);
        }

        if let Some(client) = find_client_mut_by_id(&mut self.clients, client_id) {
            let sequence = allocate_sequence(&mut client.sequence, CONNECTION_SEQUENCE_END)?;
            let packet = Packet::Payload(payload);
            let len = packet.encode(&mut self.out, self.protocol_id, Some((sequence, &client.send_key)))?;
            client.last_packet_send_time = self.current_time;

            return Ok((client.addr, &mut self.out[..len]));
        }

        Err(NetcodeError::ClientNotFound)
    }

    /// Process an packet from the especifed address. Returns a server result, check out
    /// [ServerResult].
    pub fn process_packet<'a, 's>(&'s mut self, addr: SocketAddr, buffer: &'a mut [u8]) -> ServerResult<'a, 's> {
        match self.process_packet_internal(addr, buffer) {
            Err(e) => {
                log::error!("Failed to process packet: {}", e);
                ServerResult::None
            }
            Ok(r) => r,
        }
    }

    fn process_packet_internal<'a, 's>(&'s mut self, addr: SocketAddr, buffer: &'a mut [u8]) -> Result<ServerResult<'a, 's>, NetcodeError> {
        // Handle connected client
        if let Some((slot, client)) = find_client_mut_by_addr(&mut self.clients, addr) {
            let (_, packet) = Packet::decode(
                buffer,
                self.protocol_id,
                Some(&client.receive_key),
                Some(&mut client.replay_protection),
            )?;
            log::trace!(
                "Received packet from connected client ({}): {:?}",
                client.client_id,
                packet.packet_type()
            );

            let result = match (client.state, packet) {
                (ConnectionState::Connected, Packet::Disconnect) => {
                    let client_id = client.client_id;
                    self.clients[slot] = None;
                    log::trace!("Client {} requested to disconnect", client_id);
                    return Ok(ServerResult::ClientDisconnected {
                        client_id,
                        addr,
                        payload: None,
                    });
                }
                (ConnectionState::Connected, Packet::Payload(payload)) => ServerResult::Payload {
                    client_id: client.client_id,
                    payload,
                },
                (ConnectionState::Connected, Packet::KeepAlive { .. }) => ServerResult::None,
                _ => return Ok(ServerResult::None),
            };
            if !client.confirmed {
                log::trace!("Confirmed connection for Client {}", client.client_id);
                client.confirmed = true;
            }
            client.last_packet_received_time = self.current_time;
            return Ok(result);
        }

        // Handle pending client
        if let Some(pending) = self.pending_clients.get_mut(&addr) {
            let (_, packet) = Packet::decode(
                buffer,
                self.protocol_id,
                Some(&pending.receive_key),
                Some(&mut pending.replay_protection),
            )?;
            log::trace!("Received packet from pending client ({}): {:?}", addr, packet.packet_type());
            match packet {
                Packet::ConnectionRequest {
                    protocol_id,
                    expire_timestamp,
                    data,
                    xnonce,
                    version_info,
                } => {
                    return self.handle_connection_request(addr, version_info, protocol_id, expire_timestamp, xnonce, data);
                }
                Packet::Response {
                    token_data,
                    token_sequence,
                } => {
                    let challenge_token = ChallengeToken::decode(token_data, token_sequence, &self.challenge_key)?;
                    if challenge_token.client_id != pending.client_id || challenge_token.user_data != pending.user_data {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "challenge token does not match pending connection",
                        )
                        .into());
                    }
                    // Every eligibility check runs before the pending connection is removed, so a
                    // rejected response leaves the pending connection and its token untouched.
                    let (token_mac, client_id, send_key) = (pending.token_mac, pending.client_id, pending.send_key);
                    if !self.connect_token_permits(&token_mac, addr) {
                        log::debug!("Ignored connection response from {}, connect token is not admissible.", addr);
                        return Ok(ServerResult::None);
                    }
                    if find_client_slot_by_id(&self.clients, client_id).is_some() {
                        log::debug!("Ignored connection response for Client {}, already connected.", client_id);
                        return Ok(ServerResult::None);
                    }
                    let Some(client_index) = self.clients.iter().position(|c| c.is_none()) else {
                        let sequence = allocate_sequence(&mut self.global_sequence, GLOBAL_SEQUENCE_END)?;
                        let packet = Packet::ConnectionDenied;
                        let len = packet.encode(&mut self.out, self.protocol_id, Some((sequence, &send_key)))?;
                        return Ok(ServerResult::PacketToSend {
                            addr,
                            payload: &mut self.out[..len],
                        });
                    };
                    // Consumed before the first connection-sequence packet is encrypted, and never
                    // restored, even if encoding fails below.
                    if !self.consume_connect_token(&token_mac, addr) {
                        return Ok(ServerResult::None);
                    }
                    let mut pending = self.pending_clients.remove(&addr).unwrap();
                    pending.last_packet_received_time = self.current_time;
                    let sequence = allocate_sequence(&mut pending.sequence, CONNECTION_SEQUENCE_END)?;
                    pending.state = ConnectionState::Connected;
                    pending.last_packet_send_time = self.current_time;

                    let packet = Packet::KeepAlive {
                        max_clients: self.max_clients as u32,
                        client_index: client_index as u32,
                    };
                    let len = packet.encode(&mut self.out, self.protocol_id, Some((sequence, &pending.send_key)))?;

                    let user_data: [u8; NETCODE_USER_DATA_BYTES] = pending.user_data;
                    self.clients[client_index] = Some(pending);

                    return Ok(ServerResult::ClientConnected {
                        client_id,
                        addr,
                        user_data: Box::new(user_data),
                        payload: &mut self.out[..len],
                    });
                }
                _ => return Ok(ServerResult::None),
            }
        }

        // Handle new client
        let (_, packet) = Packet::decode(buffer, self.protocol_id, None, None)?;
        match packet {
            Packet::ConnectionRequest {
                data,
                protocol_id,
                expire_timestamp,
                xnonce,
                version_info,
            } => self.handle_connection_request(addr, version_info, protocol_id, expire_timestamp, xnonce, data),
            _ => unreachable!("Decoding packet without key can only return ConnectionRequest packets"),
        }
    }

    pub fn clients_slot(&self) -> Vec<usize> {
        self.clients
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| if slot.is_some() { Some(index) } else { None })
            .collect()
    }

    /// Returns the ids from the connected clients (iterator).
    pub fn clients_id_iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.clients.iter().filter_map(|slot| slot.as_ref().map(|client| client.client_id))
    }

    /// Returns the ids from the connected clients.
    pub fn clients_id(&self) -> Vec<u64> {
        self.clients_id_iter().collect()
    }

    /// Returns the maximum number of clients that can be connected.
    pub fn max_clients(&self) -> usize {
        self.max_clients
    }

    /// Update the maximum numbers of clients that can be connected
    ///
    /// Changing the `max_clients` to a lower value than the current number of connect clients
    /// does not disconnect clients. So [`NetcodeServer::connected_clients()`] can return a
    /// higher value than [`NetcodeServer::max_clients()`].
    pub fn set_max_clients(&mut self, max_clients: usize) {
        let max_clients = max_clients.min(NETCODE_MAX_CLIENTS);
        log::debug!("Netcode max_clients set to {}", max_clients);

        self.max_clients = max_clients;
    }

    /// Returns current number of clients connected.
    pub fn connected_clients(&self) -> usize {
        self.clients.iter().filter(|slot| slot.is_some()).count()
    }

    /// Advance the server current time, and remove any pending connections that have expired.
    /// Connected clients are kept past their token expiry.
    pub fn update(&mut self, duration: Duration) {
        self.current_time += duration;

        for client in self.pending_clients.values_mut() {
            if self.current_time.as_secs() >= client.expire_timestamp {
                log::debug!("Pending Client {} disconnected, connection token expired.", client.client_id);
                client.state = ConnectionState::Disconnected;
            }
        }

        self.pending_clients.retain(|_, c| c.state != ConnectionState::Disconnected);
    }

    /// Updates the client, returns a ServerResult.
    ///
    /// # Example
    /// ```
    /// # use renetcode::ServerResult;
    /// # let mut server = renetcode::NetcodeServer::__test();
    /// for client_id in server.clients_id().into_iter() {
    ///     match server.update_client(client_id) {
    ///         ServerResult::PacketToSend { payload, addr } => send_to(payload, addr),
    ///         _ => { /* ... */ }
    ///     }
    /// }
    /// # fn send_to(p: &[u8], addr: std::net::SocketAddr) {}
    /// ```
    pub fn update_client(&mut self, client_id: u64) -> ServerResult<'_, '_> {
        let slot = match find_client_slot_by_id(&self.clients, client_id) {
            None => return ServerResult::None,
            Some(slot) => slot,
        };

        if let Some(client) = &mut self.clients[slot] {
            let connection_timed_out = client.timeout_seconds > 0
                && (client.last_packet_received_time + Duration::from_secs(client.timeout_seconds as u64) < self.current_time);
            if connection_timed_out {
                log::debug!("Client {} disconnected, connection timed out", client.client_id);
                client.state = ConnectionState::Disconnected;
            }

            if client.state == ConnectionState::Disconnected {
                let packet = Packet::Disconnect;
                let sequence = allocate_sequence(&mut client.sequence, CONNECTION_SEQUENCE_END);
                let send_key = client.send_key;
                let addr = client.addr;
                self.clients[slot] = None;

                let len = match sequence.and_then(|sequence| packet.encode(&mut self.out, self.protocol_id, Some((sequence, &send_key)))) {
                    Err(e) => {
                        log::error!("Failed to encode disconnect packet: {}", e);
                        return ServerResult::ClientDisconnected {
                            client_id,
                            addr,
                            payload: None,
                        };
                    }
                    Ok(len) => len,
                };

                return ServerResult::ClientDisconnected {
                    client_id,
                    addr,
                    payload: Some(&mut self.out[..len]),
                };
            }

            if client.last_packet_send_time + NETCODE_SEND_RATE <= self.current_time {
                let packet = Packet::KeepAlive {
                    client_index: slot as u32,
                    max_clients: self.max_clients as u32,
                };

                let len = match allocate_sequence(&mut client.sequence, CONNECTION_SEQUENCE_END)
                    .and_then(|sequence| packet.encode(&mut self.out, self.protocol_id, Some((sequence, &client.send_key))))
                {
                    Err(e) => {
                        log::error!("Failed to encode keep alive packet: {}", e);
                        return ServerResult::None;
                    }
                    Ok(len) => len,
                };
                client.last_packet_send_time = self.current_time;
                return ServerResult::PacketToSend {
                    addr: client.addr,
                    payload: &mut self.out[..len],
                };
            }
        }

        ServerResult::None
    }

    pub fn is_client_connected(&self, client_id: u64) -> bool {
        find_client_slot_by_id(&self.clients, client_id).is_some()
    }

    /// Disconnect an client and returns its address and a disconnect packet to be sent to them.
    // TODO: we can return Result<PacketToSend, NetcodeError>
    //       but the library user would need to be aware that he has to run
    //       the same code as Result::ClientDisconnected
    pub fn disconnect(&mut self, client_id: u64) -> ServerResult<'_, '_> {
        if let Some(slot) = find_client_slot_by_id(&self.clients, client_id) {
            let mut client = self.clients[slot].take().unwrap();
            let packet = Packet::Disconnect;

            let len = match allocate_sequence(&mut client.sequence, CONNECTION_SEQUENCE_END)
                .and_then(|sequence| packet.encode(&mut self.out, self.protocol_id, Some((sequence, &client.send_key))))
            {
                Err(e) => {
                    log::error!("Failed to encode disconnect packet: {}", e);
                    return ServerResult::ClientDisconnected {
                        client_id,
                        addr: client.addr,
                        payload: None,
                    };
                }
                Ok(len) => len,
            };
            return ServerResult::ClientDisconnected {
                client_id,
                addr: client.addr,
                payload: Some(&mut self.out[..len]),
            };
        }

        ServerResult::None
    }
}

/// Returns the next sequence and advances the counter, refusing once `end` is reached so a
/// sequence is never wrapped, saturated or reused under the same key.
fn allocate_sequence(next: &mut u64, end: u64) -> Result<u64, NetcodeError> {
    if *next >= end {
        return Err(io::Error::new(io::ErrorKind::Other, "packet sequence space exhausted").into());
    }
    let sequence = *next;
    *next += 1;
    Ok(sequence)
}

fn find_client_mut_by_id(clients: &mut [Option<Connection>], client_id: u64) -> Option<&mut Connection> {
    clients.iter_mut().flatten().find(|c| c.client_id == client_id)
}

fn find_client_by_id(clients: &[Option<Connection>], client_id: u64) -> Option<&Connection> {
    clients.iter().flatten().find(|c| c.client_id == client_id)
}

fn find_client_slot_by_id(clients: &[Option<Connection>], client_id: u64) -> Option<usize> {
    clients.iter().enumerate().find_map(|(i, c)| match c {
        Some(c) if c.client_id == client_id => Some(i),
        _ => None,
    })
}

fn find_client_mut_by_addr(clients: &mut [Option<Connection>], addr: SocketAddr) -> Option<(usize, &mut Connection)> {
    clients.iter_mut().enumerate().find_map(|(i, c)| match c {
        Some(c) if c.addr == addr => Some((i, c)),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        client::NetcodeClient,
        packet::{
            tests::{encrypt_raw_packet, for_each_adversarial_datagram, for_each_encoded_packet},
            PacketType,
        },
        token::{
            tests::{
                encrypted_private_token_with_addresses, fixed_connect_token, fixed_private_token, malformed_address_lists, FIXTURE_XNONCE,
            },
            ConnectToken, TokenGenerationError,
        },
        ClientAuthentication, NETCODE_CHALLENGE_TOKEN_BYTES,
    };

    use super::*;

    const TEST_KEY: &[u8; NETCODE_KEY_BYTES] = b"an example very very secret key."; // 32-bytes
    const TEST_PROTOCOL_ID: u64 = 7;

    fn new_server(current_time: Duration, authentication: ServerAuthentication) -> NetcodeServer {
        let config = ServerConfig {
            current_time,
            max_clients: 16,
            protocol_id: TEST_PROTOCOL_ID,
            public_addresses: vec!["127.0.0.1:5000".parse().unwrap()],
            authentication,
        };
        NetcodeServer::new(config)
    }

    // Fixture tokens are issued at time zero and expire at this timestamp, so it is also the
    // fixture issuer's maximum lifetime.
    const FIXTURE_EXPIRE_TIMESTAMP: u64 = 30;

    fn fixture_server() -> NetcodeServer {
        let authentication = ServerAuthentication::Secure {
            private_key: *TEST_KEY,
            max_connect_token_lifetime: Duration::from_secs(FIXTURE_EXPIRE_TIMESTAMP),
        };
        let mut server = new_server(Duration::ZERO, authentication);
        server.challenge_key = [55; NETCODE_KEY_BYTES];
        server
    }

    fn fixture_token(client_id: u64, key_byte: u8, user_data: [u8; NETCODE_USER_DATA_BYTES]) -> ConnectToken {
        let mut private = fixed_private_token(client_id, &["127.0.0.1:5000".parse().unwrap()]);
        private.client_to_server_key = [key_byte; NETCODE_KEY_BYTES];
        private.server_to_client_key = [key_byte.wrapping_add(1); NETCODE_KEY_BYTES];
        private.user_data = user_data;
        fixed_connect_token(&private, TEST_PROTOCOL_ID, 0, FIXTURE_EXPIRE_TIMESTAMP, TEST_KEY)
    }

    fn request_packet(token: &ConnectToken) -> Vec<u8> {
        let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES];
        let len = Packet::connection_request_from_token(token)
            .encode(&mut buffer, TEST_PROTOCOL_ID, None)
            .unwrap();
        buffer[..len].to_vec()
    }

    fn request_challenge(server: &mut NetcodeServer, addr: SocketAddr, token: &ConnectToken) -> (u64, [u8; NETCODE_CHALLENGE_TOKEN_BYTES]) {
        match server.process_packet(addr, &mut request_packet(token)) {
            ServerResult::PacketToSend { payload, .. } => {
                match Packet::decode(payload, TEST_PROTOCOL_ID, Some(&token.server_to_client_key), None)
                    .unwrap()
                    .1
                {
                    Packet::Challenge {
                        token_sequence,
                        token_data,
                    } => (token_sequence, token_data),
                    packet => panic!("expected challenge, got {packet:?}"),
                }
            }
            result => panic!("expected challenge, got {result:?}"),
        }
    }

    fn response_packet(token: &ConnectToken, sequence: u64, challenge: (u64, [u8; NETCODE_CHALLENGE_TOKEN_BYTES])) -> Vec<u8> {
        let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES];
        let response = Packet::Response {
            token_sequence: challenge.0,
            token_data: challenge.1,
        };
        let len = response
            .encode(&mut buffer, TEST_PROTOCOL_ID, Some((sequence, &token.client_to_server_key)))
            .unwrap();
        buffer[..len].to_vec()
    }

    fn connect_fixture_client(server: &mut NetcodeServer, addr: SocketAddr, token: &ConnectToken) {
        let challenge = request_challenge(server, addr, token);
        match server.process_packet(addr, &mut response_packet(token, 0, challenge)) {
            ServerResult::ClientConnected { client_id, user_data, .. } => {
                assert_eq!(client_id, token.client_id);
                assert_eq!(server.user_data(client_id), Some(*user_data));
            }
            result => panic!("expected connection, got {result:?}"),
        }
    }

    fn receive_state(server: &NetcodeServer) -> String {
        let mut pending: Vec<_> = server.pending_clients.iter().collect();
        pending.sort_by_key(|(addr, _)| **addr);
        let entries: Vec<_> = server.connect_token_entries.iter().flatten().collect();
        format!(
            "{:?}",
            (&server.clients, pending, entries, server.global_sequence, server.challenge_sequence)
        )
    }

    fn is_structural_connection_request(datagram: &[u8]) -> bool {
        datagram
            .first()
            .is_some_and(|prefix| prefix & 0xF == PacketType::ConnectionRequest as u8)
            && datagram.len() > 13 + 8 + 8 + NETCODE_CONNECT_TOKEN_XNONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES
    }

    #[test]
    fn adversarial_datagrams_preserve_server_receive_state() {
        let unknown_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let pending_addr: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let connected_addr: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let mut server = fixture_server();
        connect_fixture_client(&mut server, connected_addr, &fixture_token(1, 11, [44; NETCODE_USER_DATA_BYTES]));
        request_challenge(&mut server, pending_addr, &fixture_token(2, 13, [45; NETCODE_USER_DATA_BYTES]));
        server.update(Duration::from_secs(1));
        let before = receive_state(&server);

        for (addr, state) in [(unknown_addr, "unknown"), (pending_addr, "pending"), (connected_addr, "connected")] {
            let mut case = 0;
            for_each_adversarial_datagram(|datagram| {
                case += 1;
                let context = format!("{state}, case {case}, length {}", datagram.len());
                let ignored_request = state == "connected" && is_structural_connection_request(datagram);
                match server.process_packet_internal(addr, &mut datagram.to_vec()) {
                    Ok(ServerResult::None) => assert!(ignored_request, "{context}"),
                    Ok(result) => panic!("{context}: {result:?}"),
                    Err(_) => assert!(!ignored_request, "{context}"),
                }
                assert_eq!(server.process_packet(addr, &mut datagram.to_vec()), ServerResult::None, "{context}");
                assert_eq!(before, receive_state(&server), "{context}");
            });
        }
    }

    #[test]
    fn truncated_and_corrupted_client_packets_preserve_server_receive_state() {
        let unknown_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let pending_addr: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let connected_addr: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let connected = fixture_token(1, 11, [44; NETCODE_USER_DATA_BYTES]);
        let pending = fixture_token(2, 13, [45; NETCODE_USER_DATA_BYTES]);
        let mut server = fixture_server();
        connect_fixture_client(&mut server, connected_addr, &connected);
        request_challenge(&mut server, pending_addr, &pending);
        server.update(Duration::from_secs(1));
        let before = receive_state(&server);

        for (addr, state, key) in [
            (unknown_addr, "unknown", connected.client_to_server_key),
            (pending_addr, "pending", pending.client_to_server_key),
            (connected_addr, "connected", connected.client_to_server_key),
        ] {
            for_each_encoded_packet(TEST_PROTOCOL_ID, &key, |sequence, packet, encoded| {
                let request = matches!(packet, Packet::ConnectionRequest { .. });
                let mut malformed: Vec<(String, Vec<u8>)> = (0..encoded.len())
                    .map(|len| (format!("prefix length {len}"), encoded[..len].to_vec()))
                    .collect();
                if !request {
                    let body_end = encoded.len() - NETCODE_MAC_BYTES;
                    for index in (0..10.min(body_end)).chain([body_end - 1]).chain(body_end..encoded.len()) {
                        let mut corrupt = encoded.to_vec();
                        corrupt[index] ^= 0x01;
                        malformed.push((format!("bit flip at {index}"), corrupt));
                    }
                }
                if state == "unknown" || request {
                    malformed.push(("complete".to_string(), encoded.to_vec()));
                }
                for (case, mut bytes) in malformed {
                    let context = format!("{state}, {packet:?} at {sequence}, {case}");
                    assert_eq!(server.process_packet(addr, &mut bytes), ServerResult::None, "{context}");
                    assert_eq!(before, receive_state(&server), "{context}");
                }
            });
        }
    }

    #[test]
    fn rejected_packets_do_not_refresh_server_liveness() {
        let pending_addr: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let connected_addr: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let connected = fixture_token(1, 11, [44; NETCODE_USER_DATA_BYTES]);
        let pending = fixture_token(2, 13, [45; NETCODE_USER_DATA_BYTES]);
        let mut server = fixture_server();
        connect_fixture_client(&mut server, connected_addr, &connected);
        let challenge = request_challenge(&mut server, pending_addr, &pending);
        server.update(Duration::from_secs(3));

        let mut forged_request = request_packet(&connected);
        *forged_request.last_mut().unwrap() ^= 1;
        let short_keep_alive = encrypt_raw_packet(PacketType::KeepAlive, 5, &[0; 7], TEST_PROTOCOL_ID, &connected.client_to_server_key);
        let connected_before = format!("{:?}", server.clients);
        assert!(matches!(
            server.process_packet_internal(connected_addr, &mut forged_request.clone()),
            Ok(ServerResult::None)
        ));
        assert!(matches!(
            server.process_packet_internal(connected_addr, &mut short_keep_alive.clone()),
            Err(NetcodeError::IoError(_))
        ));
        assert_eq!(connected_before, format!("{:?}", server.clients));
        assert_eq!(server.time_since_last_received_packet(1), Some(Duration::from_secs(3)));

        let mut forged_pending_request = request_packet(&pending);
        *forged_pending_request.last_mut().unwrap() ^= 1;
        let mut forged_challenge = challenge;
        forged_challenge.1[0] ^= 1;
        let pending_before = format!("{:?}", server.pending_clients[&pending_addr]);
        assert!(matches!(
            server.process_packet_internal(pending_addr, &mut forged_pending_request),
            Err(NetcodeError::TokenGenerationError(TokenGenerationError::CryptoError))
        ));
        assert!(matches!(
            server.process_packet_internal(pending_addr, &mut response_packet(&pending, 0, forged_challenge)),
            Err(NetcodeError::CryptoError)
        ));
        assert_eq!(pending_before, format!("{:?}", server.pending_clients[&pending_addr]));
        assert_eq!(server.pending_clients[&pending_addr].last_packet_received_time, Duration::ZERO);

        let mut keep_alive = [0u8; NETCODE_MAX_PACKET_BYTES];
        let len = Packet::KeepAlive {
            client_index: 0,
            max_clients: 0,
        }
        .encode(&mut keep_alive, TEST_PROTOCOL_ID, Some((5, &connected.client_to_server_key)))
        .unwrap();
        assert_eq!(server.process_packet(connected_addr, &mut keep_alive[..len]), ServerResult::None);
        assert_eq!(server.time_since_last_received_packet(1), Some(Duration::ZERO));

        request_challenge(&mut server, pending_addr, &pending);
        assert_eq!(
            server.pending_clients[&pending_addr].last_packet_received_time,
            Duration::from_secs(3)
        );
        server.update(Duration::from_secs(1));
        match server.process_packet(pending_addr, &mut response_packet(&pending, 1, challenge)) {
            ServerResult::ClientConnected { client_id, .. } => assert_eq!(client_id, 2),
            result => panic!("expected connection, got {result:?}"),
        }
        assert_eq!(server.time_since_last_received_packet(2), Some(Duration::ZERO));

        assert_eq!(server.time_since_last_received_packet(1), Some(Duration::from_secs(1)));
        for _ in 0..4 {
            server.update(Duration::from_secs(1));
            assert_eq!(
                server.process_packet(connected_addr, &mut forged_request.clone()),
                ServerResult::None
            );
            assert_eq!(
                server.process_packet(connected_addr, &mut short_keep_alive.clone()),
                ServerResult::None
            );
            assert!(!matches!(server.update_client(1), ServerResult::ClientDisconnected { .. }));
        }
        server.update(Duration::from_secs(1));
        assert!(matches!(
            server.update_client(1),
            ServerResult::ClientDisconnected { client_id: 1, .. }
        ));
    }

    #[test]
    fn challenge_response_must_match_pending_identity() {
        let addr_a: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let cases = [
            (
                "different client id",
                1,
                2,
                [44; NETCODE_USER_DATA_BYTES],
                [45; NETCODE_USER_DATA_BYTES],
            ),
            (
                "same client id, different user data",
                3,
                3,
                [46; NETCODE_USER_DATA_BYTES],
                [47; NETCODE_USER_DATA_BYTES],
            ),
        ];

        for (case, id_a, id_b, user_a, user_b) in cases {
            let token_a = fixture_token(id_a, 11, user_a);
            let token_b = fixture_token(id_b, 13, user_b);
            let mut server = fixture_server();
            let challenge_a = request_challenge(&mut server, addr_a, &token_a);
            let challenge_b = request_challenge(&mut server, addr_b, &token_b);
            let pending_before = format!("{:?}", server.pending_clients[&addr_b]);

            let mut crossed = response_packet(&token_b, 0, challenge_a);
            match server.process_packet_internal(addr_b, &mut crossed) {
                Err(NetcodeError::IoError(error)) => assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{case}"),
                result => panic!("{case}: {result:?}"),
            }
            assert_eq!(server.connected_clients(), 0, "{case}");
            assert_eq!(pending_before, format!("{:?}", server.pending_clients[&addr_b]), "{case}");

            match server.process_packet(addr_b, &mut response_packet(&token_b, 1, challenge_b)) {
                ServerResult::ClientConnected { client_id, user_data, .. } => {
                    assert_eq!(client_id, id_b, "{case}");
                    assert_eq!(*user_data, user_b, "{case}");
                }
                result => panic!("{case}: {result:?}"),
            }
            assert_eq!(server.user_data(id_b), Some(user_b), "{case}");
        }
    }

    #[test]
    fn mismatched_challenge_cannot_duplicate_a_connected_identity() {
        let first_addr: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let second_addr: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let other_addr: SocketAddr = "127.0.0.1:3003".parse().unwrap();
        let first = fixture_token(7, 11, [44; NETCODE_USER_DATA_BYTES]);
        let second = fixture_token(7, 13, [44; NETCODE_USER_DATA_BYTES]);
        let other = fixture_token(8, 15, [44; NETCODE_USER_DATA_BYTES]);
        let mut server = fixture_server();
        let first_challenge = request_challenge(&mut server, first_addr, &first);
        let second_challenge = request_challenge(&mut server, second_addr, &second);
        let other_challenge = request_challenge(&mut server, other_addr, &other);
        assert!(matches!(
            server.process_packet(first_addr, &mut response_packet(&first, 0, first_challenge)),
            ServerResult::ClientConnected { client_id: 7, .. }
        ));

        let mut crossed = response_packet(&second, 0, other_challenge);
        assert!(server.process_packet_internal(second_addr, &mut crossed).is_err());
        assert_eq!(server.clients_id(), vec![7]);
        assert!(server.pending_clients.contains_key(&second_addr));

        let pending = format!("{:?}", server.pending_clients[&second_addr]);
        assert_eq!(
            server.process_packet(second_addr, &mut response_packet(&second, 1, second_challenge)),
            ServerResult::None
        );
        assert_eq!(server.clients_id(), vec![7]);
        assert_eq!(pending, format!("{:?}", server.pending_clients[&second_addr]));

        // The rejected response left the pending connection and its token admissible.
        server.disconnect(7);
        assert!(matches!(
            server.process_packet(second_addr, &mut response_packet(&second, 2, second_challenge)),
            ServerResult::ClientConnected { client_id: 7, .. }
        ));
    }

    #[test]
    fn connection_request_requires_authenticated_well_formed_token() {
        let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let token = fixture_token(1, 11, [44; NETCODE_USER_DATA_BYTES]);
        let request = |version_info: [u8; 13], protocol_id: u64, expire_timestamp: u64, data: [u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES]| {
            let mut buffer = [0u8; NETCODE_MAX_PACKET_BYTES];
            let packet = Packet::ConnectionRequest {
                version_info,
                protocol_id,
                expire_timestamp,
                xnonce: FIXTURE_XNONCE,
                data,
            };
            let len = packet.encode(&mut buffer, protocol_id, None).unwrap();
            buffer[..len].to_vec()
        };
        let mut wrong_version = *NETCODE_VERSION_INFO;
        wrong_version[8] = b'9';
        let mut wrong_tag = token.private_data;
        wrong_tag[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - 1] ^= 1;
        let valid = (
            *NETCODE_VERSION_INFO,
            TEST_PROTOCOL_ID,
            FIXTURE_EXPIRE_TIMESTAMP,
            token.private_data,
        );

        let mut server = fixture_server();
        let before = receive_state(&server);
        let reject = |server: &mut NetcodeServer, bytes: Vec<u8>, case: &str, expected: fn(&NetcodeError) -> bool| {
            match server.process_packet_internal(addr, &mut bytes.clone()) {
                Err(error) => assert!(expected(&error), "{case}: {error:?}"),
                Ok(result) => panic!("{case}: {result:?}"),
            }
            assert_eq!(before, receive_state(server), "{case}");
        };

        reject(&mut server, request(wrong_version, valid.1, valid.2, valid.3), "version", |e| {
            matches!(e, NetcodeError::InvalidVersion)
        });
        reject(
            &mut server,
            request(valid.0, TEST_PROTOCOL_ID + 1, valid.2, valid.3),
            "protocol",
            |e| matches!(e, NetcodeError::InvalidProtocolID),
        );
        reject(
            &mut server,
            request(valid.0, valid.1, valid.2 + 1, valid.3),
            "expiry in additional data",
            |e| matches!(e, NetcodeError::TokenGenerationError(TokenGenerationError::CryptoError)),
        );
        reject(
            &mut server,
            request(valid.0, valid.1, valid.2, wrong_tag),
            "private token tag",
            |e| matches!(e, NetcodeError::TokenGenerationError(TokenGenerationError::CryptoError)),
        );
        for (case, addresses) in malformed_address_lists() {
            let data = encrypted_private_token_with_addresses(&addresses, TEST_PROTOCOL_ID, FIXTURE_EXPIRE_TIMESTAMP, TEST_KEY);
            reject(
                &mut server,
                request(valid.0, valid.1, valid.2, data),
                case,
                |e| matches!(e, NetcodeError::TokenGenerationError(TokenGenerationError::IoError(io)) if io.kind() == std::io::ErrorKind::InvalidData),
            );
        }

        let mut expired_server = fixture_server();
        expired_server.update(Duration::from_secs(FIXTURE_EXPIRE_TIMESTAMP));
        let mut expired = request(valid.0, valid.1, valid.2, valid.3);
        assert!(matches!(
            expired_server.process_packet_internal(addr, &mut expired),
            Err(NetcodeError::Expired)
        ));
        assert!(expired_server.pending_clients.is_empty());

        let mixed: Vec<SocketAddr> = (0..32u16)
            .map(|i| match i {
                31 => "127.0.0.1:5000".parse().unwrap(),
                _ if i % 2 == 0 => SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0),
                _ => SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), i),
            })
            .collect();
        let mut private = fixed_private_token(1, &mixed);
        private.client_to_server_key = token.client_to_server_key;
        private.server_to_client_key = token.server_to_client_key;
        let mixed_token = fixed_connect_token(&private, TEST_PROTOCOL_ID, 0, FIXTURE_EXPIRE_TIMESTAMP, TEST_KEY);
        request_challenge(&mut server, addr, &mixed_token);
        assert_eq!(server.pending_clients[&addr].client_id, 1);
    }

    #[test]
    fn sequence_zero_disconnect_disconnects_connected_client() {
        let addr: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let token = fixture_token(1, 11, [44; NETCODE_USER_DATA_BYTES]);
        let mut server = fixture_server();
        connect_fixture_client(&mut server, addr, &token);

        let mut disconnect = [0u8; NETCODE_MAX_PACKET_BYTES];
        let len = Packet::Disconnect
            .encode(&mut disconnect, TEST_PROTOCOL_ID, Some((0, &token.client_to_server_key)))
            .unwrap();
        assert_eq!(len, 1 + NETCODE_MAC_BYTES);
        assert_eq!(
            server.process_packet(addr, &mut disconnect[..len]),
            ServerResult::ClientDisconnected {
                client_id: 1,
                addr,
                payload: None
            }
        );
        assert!(!server.is_client_connected(1));
    }

    fn sent(payload: &[u8], token: &ConnectToken) -> (u64, PacketType) {
        let mut buffer = payload.to_vec();
        let (sequence, packet) = Packet::decode(&mut buffer, TEST_PROTOCOL_ID, Some(&token.server_to_client_key), None).unwrap();
        (sequence, packet.packet_type())
    }

    fn is_exhausted(result: Result<ServerResult, NetcodeError>) -> bool {
        matches!(result, Err(NetcodeError::IoError(error)) if error.kind() == std::io::ErrorKind::Other)
    }

    #[test]
    fn global_and_connection_packets_never_share_a_sequence_under_one_key() {
        let addrs: [SocketAddr; 3] = ["127.0.0.1:3001", "127.0.0.1:3002", "127.0.0.1:3003"].map(|addr| addr.parse().unwrap());
        let connected = fixture_token(1, 11, [44; NETCODE_USER_DATA_BYTES]);
        let denied = fixture_token(2, 13, [45; NETCODE_USER_DATA_BYTES]);
        let full = fixture_token(3, 15, [46; NETCODE_USER_DATA_BYTES]);
        let mut server = fixture_server();
        server.clients = vec![None; 1].into_boxed_slice();
        server.set_max_clients(1);
        let authentication = ClientAuthentication::Secure {
            connect_token: connected.clone(),
        };
        let mut client = NetcodeClient::new(Duration::ZERO, authentication).unwrap();
        let mut global = Vec::new();
        let mut connection = Vec::new();

        let (request, _) = client.update(Duration::ZERO).unwrap();
        match server.process_packet(addrs[0], request) {
            ServerResult::PacketToSend { payload, .. } => {
                global.push(sent(payload, &connected));
                assert_eq!(client.process_packet(payload), None);
            }
            result => panic!("expected challenge, got {result:?}"),
        }

        let mut denied_challenge = None;
        for _ in 0..2 {
            match server.process_packet(addrs[1], &mut request_packet(&denied)) {
                ServerResult::PacketToSend { payload, .. } => {
                    global.push(sent(payload, &denied));
                    match Packet::decode(payload, TEST_PROTOCOL_ID, Some(&denied.server_to_client_key), None)
                        .unwrap()
                        .1
                    {
                        Packet::Challenge {
                            token_sequence,
                            token_data,
                        } => denied_challenge = Some((token_sequence, token_data)),
                        packet => panic!("expected challenge, got {packet:?}"),
                    }
                }
                result => panic!("expected challenge, got {result:?}"),
            }
        }

        let (response, _) = client.update(Duration::ZERO).unwrap();
        match server.process_packet(addrs[0], response) {
            ServerResult::ClientConnected { payload, .. } => {
                connection.push(sent(payload, &connected));
                assert_eq!(client.process_packet(payload), None);
            }
            result => panic!("expected connection, got {result:?}"),
        }
        assert!(client.is_connected());

        let (_, payload) = server.generate_payload_packet(1, &[42]).unwrap();
        connection.push(sent(payload, &connected));
        assert_eq!(client.process_packet(payload), Some(&[42][..]));

        match server.process_packet(addrs[1], &mut response_packet(&denied, 0, denied_challenge.unwrap())) {
            ServerResult::PacketToSend { payload, .. } => global.push(sent(payload, &denied)),
            result => panic!("expected denial, got {result:?}"),
        }
        match server.process_packet(addrs[2], &mut request_packet(&full)) {
            ServerResult::PacketToSend { payload, .. } => global.push(sent(payload, &full)),
            result => panic!("expected denial, got {result:?}"),
        }

        let global_start = 1u64 << 63;
        let global_sequences: Vec<u64> = global.iter().map(|(sequence, _)| *sequence).collect();
        let connection_sequences: Vec<u64> = connection.iter().map(|(sequence, _)| *sequence).collect();
        assert_eq!(global_sequences, (global_start..global_start + 5).collect::<Vec<_>>());
        assert_eq!(connection_sequences, vec![0, 1]);
        assert!(matches!(global[0].1, PacketType::Challenge));
        assert!(matches!(global[2].1, PacketType::Challenge));
        assert!(matches!(global[3].1, PacketType::ConnectionDenied));
        assert!(matches!(global[4].1, PacketType::ConnectionDenied));
        assert!(matches!(connection[0].1, PacketType::KeepAlive));
        assert!(matches!(connection[1].1, PacketType::Payload));
    }

    #[test]
    fn exhausted_server_sequences_refuse_without_wrapping() {
        let addr_a: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let token_a = fixture_token(1, 11, [44; NETCODE_USER_DATA_BYTES]);
        let token_b = fixture_token(2, 13, [45; NETCODE_USER_DATA_BYTES]);

        let mut server = fixture_server();
        server.clients = Vec::new().into_boxed_slice();
        server.global_sequence = u64::MAX - 1;
        let challenge = request_challenge(&mut server, addr_a, &token_a);
        assert_eq!(server.global_sequence, u64::MAX);
        let before = receive_state(&server);
        assert!(is_exhausted(server.process_packet_internal(addr_a, &mut request_packet(&token_a))));
        assert_eq!(before, receive_state(&server));
        assert!(is_exhausted(
            server.process_packet_internal(addr_a, &mut response_packet(&token_a, 0, challenge))
        ));
        server.set_max_clients(0);
        assert!(is_exhausted(server.process_packet_internal(addr_b, &mut request_packet(&token_b))));
        assert!(!server.pending_clients.contains_key(&addr_b));
        assert_eq!(server.global_sequence, u64::MAX);

        let connection_end = (1u64 << 63) - 1;
        let mut server = fixture_server();
        let challenge = request_challenge(&mut server, addr_a, &token_a);
        server.pending_clients.get_mut(&addr_a).unwrap().sequence = connection_end;
        assert!(is_exhausted(
            server.process_packet_internal(addr_a, &mut response_packet(&token_a, 0, challenge))
        ));
        assert!(!server.is_client_connected(1));
        assert_eq!(server.process_packet(addr_a, &mut request_packet(&token_a)), ServerResult::None);

        let token_a = fixture_token(1, 17, [44; NETCODE_USER_DATA_BYTES]);
        connect_fixture_client(&mut server, addr_a, &token_a);
        connect_fixture_client(&mut server, addr_b, &token_b);
        find_client_mut_by_id(&mut server.clients, 1).unwrap().sequence = connection_end - 1;
        let (_, payload) = server.generate_payload_packet(1, &[42]).unwrap();
        assert_eq!(sent(payload, &token_a).0, connection_end - 1);
        assert!(matches!(
            server.generate_payload_packet(1, &[42]),
            Err(NetcodeError::IoError(error)) if error.kind() == std::io::ErrorKind::Other
        ));
        assert_eq!(find_client_by_id(&server.clients, 1).unwrap().sequence, connection_end);
        server.update(NETCODE_SEND_RATE);
        assert_eq!(server.update_client(1), ServerResult::None);
        assert_eq!(find_client_by_id(&server.clients, 1).unwrap().sequence, connection_end);
        assert_eq!(
            server.disconnect(1),
            ServerResult::ClientDisconnected {
                client_id: 1,
                addr: addr_a,
                payload: None
            }
        );

        let timed_out = find_client_mut_by_id(&mut server.clients, 2).unwrap();
        timed_out.sequence = connection_end;
        timed_out.state = ConnectionState::Disconnected;
        assert_eq!(
            server.update_client(2),
            ServerResult::ClientDisconnected {
                client_id: 2,
                addr: addr_b,
                payload: None
            }
        );
    }

    #[test]
    fn server_connection() {
        let expire_seconds = 3;
        let authentication = ServerAuthentication::Secure {
            private_key: *TEST_KEY,
            max_connect_token_lifetime: Duration::from_secs(expire_seconds),
        };
        let mut server = new_server(Duration::ZERO, authentication);
        let server_addresses: Vec<SocketAddr> = server.addresses();
        let user_data = generate_random_bytes();
        let client_id = 4;
        let timeout_seconds = 5;
        let client_addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
        let connect_token = ConnectToken::generate(
            Duration::ZERO,
            TEST_PROTOCOL_ID,
            expire_seconds,
            client_id,
            timeout_seconds,
            server_addresses,
            Some(&user_data),
            TEST_KEY,
        )
        .unwrap();
        let client_auth = ClientAuthentication::Secure { connect_token };
        let mut client = NetcodeClient::new(Duration::ZERO, client_auth).unwrap();
        let (client_packet, _) = client.update(Duration::ZERO).unwrap();

        let result = server.process_packet(client_addr, client_packet);
        assert!(matches!(result, ServerResult::PacketToSend { .. }));
        match result {
            ServerResult::PacketToSend { payload, .. } => client.process_packet(payload),
            _ => unreachable!(),
        };

        assert!(!client.is_connected());
        let (client_packet, _) = client.update(Duration::ZERO).unwrap();
        let result = server.process_packet(client_addr, client_packet);

        match result {
            ServerResult::ClientConnected {
                client_id: r_id,
                user_data: r_data,
                payload,
                ..
            } => {
                assert_eq!(client_id, r_id);
                assert_eq!(user_data, *r_data);
                client.process_packet(payload)
            }
            _ => unreachable!(),
        };

        assert!(client.is_connected());

        for _ in 0..3 {
            let payload = [7u8; 300];
            let (_, packet) = server.generate_payload_packet(client_id, &payload).unwrap();
            let result_payload = client.process_packet(packet).unwrap();
            assert_eq!(payload, result_payload);
        }

        let result = server.update_client(client_id);
        assert_eq!(result, ServerResult::None);
        server.update(NETCODE_SEND_RATE);

        let result = server.update_client(client_id);
        match result {
            ServerResult::PacketToSend { payload, .. } => {
                assert!(client.process_packet(payload).is_none());
            }
            _ => unreachable!(),
        }

        let client_payload = [2u8; 300];
        let (_, packet) = client.generate_payload_packet(&client_payload).unwrap();

        match server.process_packet(client_addr, packet) {
            ServerResult::Payload { client_id: id, payload } => {
                assert_eq!(id, client_id);
                assert_eq!(client_payload, payload);
            }
            _ => unreachable!(),
        }

        assert!(server.is_client_connected(client_id));
        let result = server.disconnect(client_id);
        match result {
            ServerResult::ClientDisconnected {
                payload: Some(payload), ..
            } => {
                assert!(client.is_connected());
                assert!(client.process_packet(payload).is_none());
                assert!(!client.is_connected());
            }
            _ => unreachable!(),
        }

        assert!(!server.is_client_connected(client_id));
    }

    fn issued_token(minted_at: Duration, client_id: u64, private_key: &[u8; NETCODE_KEY_BYTES]) -> ConnectToken {
        let server_addresses = vec!["127.0.0.1:5000".parse().unwrap()];
        ConnectToken::generate(minted_at, TEST_PROTOCOL_ID, 30, client_id, 5, server_addresses, None, private_key).unwrap()
    }

    fn history_filler_addr(index: usize) -> SocketAddr {
        SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 4000 + index as u16)
    }

    fn assert_denied(server: &mut NetcodeServer, addr: SocketAddr, token: &ConnectToken) {
        match server.process_packet(addr, &mut request_packet(token)) {
            ServerResult::PacketToSend { payload, .. } => assert!(matches!(sent(payload, token).1, PacketType::ConnectionDenied)),
            result => panic!("expected denial, got {result:?}"),
        }
    }

    #[test]
    fn consumed_connect_token_cannot_connect_again() {
        let addr: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let other_addr: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let cases = [
            (
                "secure",
                ServerAuthentication::Secure {
                    private_key: *TEST_KEY,
                    max_connect_token_lifetime: Duration::from_secs(30),
                },
                *TEST_KEY,
            ),
            ("unsecure", ServerAuthentication::Unsecure, [0; NETCODE_KEY_BYTES]),
        ];

        for (case, authentication, key) in cases {
            let used = issued_token(Duration::ZERO, 1, &key);
            let mut server = new_server(Duration::ZERO, authentication);
            connect_fixture_client(&mut server, addr, &used);
            assert!(
                matches!(server.disconnect(1), ServerResult::ClientDisconnected { client_id: 1, .. }),
                "{case}"
            );

            for replay_addr in [addr, other_addr] {
                assert_eq!(
                    server.process_packet(replay_addr, &mut request_packet(&used)),
                    ServerResult::None,
                    "{case}, {replay_addr}"
                );
            }
            assert!(server.pending_clients.is_empty(), "{case}");
            assert_eq!(server.connected_clients(), 0, "{case}");

            connect_fixture_client(&mut server, addr, &issued_token(Duration::ZERO, 1, &key));
            assert_eq!(server.clients_id(), vec![1], "{case}");
        }
    }

    #[test]
    fn pending_token_stays_at_its_address_and_a_new_token_replaces_it() {
        let addr: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let other_addr: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let displaced = fixture_token(1, 11, [44; NETCODE_USER_DATA_BYTES]);
        let replacement = fixture_token(1, 13, [44; NETCODE_USER_DATA_BYTES]);
        let mut server = fixture_server();

        let displaced_challenge = request_challenge(&mut server, addr, &displaced);
        let retained = format!("{:?}", server.pending_clients[&addr]);
        request_challenge(&mut server, addr, &displaced);
        assert_eq!(retained, format!("{:?}", server.pending_clients[&addr]));
        assert_eq!(
            server.process_packet(other_addr, &mut request_packet(&displaced)),
            ServerResult::None
        );
        assert!(!server.pending_clients.contains_key(&other_addr));

        let replacement_challenge = request_challenge(&mut server, addr, &replacement);
        let pending = format!("{:?}", server.pending_clients[&addr]);
        assert_eq!(
            server.process_packet(addr, &mut response_packet(&displaced, 0, displaced_challenge)),
            ServerResult::None
        );
        assert_eq!(pending, format!("{:?}", server.pending_clients[&addr]));
        assert_eq!(server.connected_clients(), 0);

        match server.process_packet(addr, &mut response_packet(&replacement, 0, replacement_challenge)) {
            ServerResult::ClientConnected { client_id, payload, .. } => {
                assert_eq!(client_id, 1);
                assert!(matches!(sent(payload, &replacement), (0, PacketType::KeepAlive)));
            }
            result => panic!("expected connection, got {result:?}"),
        }
    }

    #[test]
    fn full_token_history_refuses_new_tokens_and_keeps_consumed_ones() {
        let consumed_addr: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let consumed = fixture_token(0, 11, [44; NETCODE_USER_DATA_BYTES]);
        let mut server = fixture_server();
        connect_fixture_client(&mut server, consumed_addr, &consumed);
        server.disconnect(0);

        // Denied requests are still recorded, so the history fills without filling the pending map.
        server.set_max_clients(0);
        let capacity = server.connect_token_entries.len();
        for index in 1..capacity {
            assert_denied(
                &mut server,
                history_filler_addr(index),
                &fixture_token(index as u64, 11, [44; NETCODE_USER_DATA_BYTES]),
            );
        }
        assert!(server.pending_clients.is_empty());

        let before = receive_state(&server);
        let refused = fixture_token(capacity as u64, 11, [44; NETCODE_USER_DATA_BYTES]);
        assert_eq!(
            server.process_packet(history_filler_addr(capacity), &mut request_packet(&refused)),
            ServerResult::None
        );
        assert_eq!(
            server.process_packet(consumed_addr, &mut request_packet(&consumed)),
            ServerResult::None
        );
        assert_eq!(before, receive_state(&server));

        server.set_max_clients(16);
        connect_fixture_client(
            &mut server,
            history_filler_addr(1),
            &fixture_token(1, 11, [44; NETCODE_USER_DATA_BYTES]),
        );
        assert_eq!(server.clients_id(), vec![1]);
    }

    #[test]
    fn token_expiry_ends_admission_but_not_established_connections() {
        let connected_addr: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let pending_addr: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let connected = fixture_token(1, 11, [44; NETCODE_USER_DATA_BYTES]);
        let pending = fixture_token(2, 13, [45; NETCODE_USER_DATA_BYTES]);
        let later = |create_timestamp: u64| {
            let private = fixed_private_token(3, &["127.0.0.1:5000".parse().unwrap()]);
            fixed_connect_token(&private, TEST_PROTOCOL_ID, create_timestamp, create_timestamp + 30, TEST_KEY)
        };
        let mut server = fixture_server();
        connect_fixture_client(&mut server, connected_addr, &connected);
        let stale_challenge = request_challenge(&mut server, pending_addr, &pending);
        server.set_max_clients(1);
        let capacity = server.connect_token_entries.len();
        for index in 2..capacity {
            assert_denied(
                &mut server,
                history_filler_addr(index),
                &fixture_token(index as u64 + 1, 11, [44; NETCODE_USER_DATA_BYTES]),
            );
        }
        server.set_max_clients(16);

        server.update(Duration::from_secs(29));
        assert_eq!(
            server.process_packet(pending_addr, &mut request_packet(&later(29))),
            ServerResult::None
        );
        assert!(server.pending_clients.contains_key(&pending_addr));

        server.update(Duration::from_secs(1));
        assert!(server.pending_clients.is_empty());
        assert_eq!(
            server.process_packet(pending_addr, &mut response_packet(&pending, 0, stale_challenge)),
            ServerResult::None
        );
        assert!(matches!(
            server.process_packet_internal(pending_addr, &mut request_packet(&pending)),
            Err(NetcodeError::Expired)
        ));

        let reclaiming = later(30);
        let challenge = request_challenge(&mut server, pending_addr, &reclaiming);
        assert_eq!(
            server.process_packet(pending_addr, &mut response_packet(&pending, 1, stale_challenge)),
            ServerResult::None
        );
        assert!(matches!(
            server.process_packet(pending_addr, &mut response_packet(&reclaiming, 0, challenge)),
            ServerResult::ClientConnected { client_id: 3, .. }
        ));

        server.update(Duration::from_secs(100));
        let mut payload = [0u8; NETCODE_MAX_PACKET_BYTES];
        let len = Packet::Payload(&[7])
            .encode(&mut payload, TEST_PROTOCOL_ID, Some((1, &connected.client_to_server_key)))
            .unwrap();
        assert_eq!(
            server.process_packet(connected_addr, &mut payload[..len]),
            ServerResult::Payload {
                client_id: 1,
                payload: &[7]
            }
        );
        assert!(!matches!(server.update_client(1), ServerResult::ClientDisconnected { .. }));
        let (_, reply) = server.generate_payload_packet(1, &[8]).unwrap();
        assert!(matches!(sent(reply, &connected).1, PacketType::Payload));
    }

    #[test]
    fn restarted_secure_server_refuses_tokens_issued_before_its_startup() {
        let addr: SocketAddr = "127.0.0.1:3001".parse().unwrap();
        let other_addr: SocketAddr = "127.0.0.1:3002".parse().unwrap();
        let secure = || ServerAuthentication::Secure {
            private_key: *TEST_KEY,
            max_connect_token_lifetime: Duration::from_secs(30),
        };
        let replayed = issued_token(Duration::from_secs(100), 1, TEST_KEY);
        assert_eq!(replayed.expire_timestamp, 130);

        let mut before_restart = new_server(Duration::from_secs(100), secure());
        connect_fixture_client(&mut before_restart, addr, &replayed);

        let startup = Duration::from_secs(100) + Duration::from_millis(500);
        let mut restarted = new_server(startup, secure());
        let before = receive_state(&restarted);
        assert!(matches!(
            restarted.process_packet_internal(addr, &mut request_packet(&replayed)),
            Err(NetcodeError::Expired)
        ));
        assert_eq!(before, receive_state(&restarted));
        connect_fixture_client(&mut restarted, addr, &issued_token(Duration::from_secs(101), 1, TEST_KEY));

        // Advancing the server clock does not move the startup cutoff.
        restarted.update(Duration::from_secs(20));
        assert!(matches!(
            restarted.process_packet_internal(other_addr, &mut request_packet(&replayed)),
            Err(NetcodeError::Expired)
        ));
        connect_fixture_client(&mut restarted, other_addr, &issued_token(Duration::from_secs(120), 2, TEST_KEY));

        let mut unsecure = new_server(startup, ServerAuthentication::Unsecure);
        connect_fixture_client(
            &mut unsecure,
            addr,
            &issued_token(Duration::from_secs(100), 1, &[0; NETCODE_KEY_BYTES]),
        );
        let expiring = issued_token(Duration::from_secs(100), 2, &[0; NETCODE_KEY_BYTES]);
        unsecure.update(Duration::from_millis(29_500));
        assert!(matches!(
            unsecure.process_packet_internal(other_addr, &mut request_packet(&expiring)),
            Err(NetcodeError::Expired)
        ));
    }

    #[test]
    fn secure_lifetime_must_be_whole_seconds_with_a_representable_cutoff() {
        let constructs = |current_time: Duration, max_connect_token_lifetime: Duration| {
            std::panic::catch_unwind(|| {
                new_server(
                    current_time,
                    ServerAuthentication::Secure {
                        private_key: *TEST_KEY,
                        max_connect_token_lifetime,
                    },
                )
            })
            .is_ok()
        };

        assert!(constructs(Duration::from_secs(u64::MAX - 30), Duration::from_secs(30)));
        assert!(!constructs(Duration::from_secs(100), Duration::ZERO));
        assert!(!constructs(Duration::from_secs(100), Duration::from_millis(30_500)));
        assert!(!constructs(Duration::MAX, Duration::from_secs(1)));
        assert!(!constructs(Duration::new(u64::MAX - 30, 1), Duration::from_secs(30)));
    }
}
