use std::{net::SocketAddr, sync::Arc, time::Duration};

use argh::FromArgs;

use tokio::sync::mpsc::Sender;

#[derive(FromArgs)]
/// Expose UDP port externally using helper hosts
struct Args {
    /// UDP socket address to bind to
    #[argh(positional)]
    listen_addr: SocketAddr,

    /// client mode: expose specified UDP socket
    #[argh(option, short = 'c')]
    local_connect_addr: Option<SocketAddr>,

    /// client mode: use specified server
    #[argh(option, short = 'a')]
    server_addr: Option<SocketAddr>,

    /// server mode
    #[argh(switch, short = 's')]
    server_mode: bool,

    /// maximum number of clients (LRU-style)
    #[argh(option, short = 'n', default = "4")]
    max_clients: usize,

    /// for client mode, keepalive interval
    #[argh(option, short = 'i', default = "25000")]
    ping_interval_ms: u64,

    /// pre-shared key / password to protect server against unsolicited clients
    #[argh(option, short = 'P')]
    password: Option<String>,

    /// inserad of operating as a client or server, obtain a stats block from a given server and dump it as JSON to stdout
    #[argh(switch, short = 'S')]
    dump_stats: bool,
}

#[derive(Default)]
#[cfg_attr(feature = "stats", derive(bincode::Encode))]
#[cfg_attr(
    feature = "stats_display",
    derive(serde_derive::Serialize, bincode::Decode)
)]
struct Stats {
    err1: u64,
    signed_looking: u64,
    refresh_address: u64,
    invalid_auths: u64,
    auth_in_progress: u64,
    auth_completeds: u64,
    err2: u64,
    simple_keepalives: u64,
    simple_address_switches: u64,
    dwarfs: u64,
    ch_not_founds: u64,
    err3: u64,
    dropped_no_client_address: u64,
    new_connectees: u64,
    err4: u64,
    from_connectee_bytes: u64,
    from_connectee_msgs: u64,
    from_client_bytes: u64,
    from_client_msgs: u64,
    stats_requests: u64,
    last_ka_s: u64,
    last_client_s: u64,
    last_connectee_s: u64,
}

fn get_unixtime() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(feature = "signed_keepalives")]
mod signed_keepalives {
    use hmac::{Hmac, Mac};
    use jwt::{SignWithKey, VerifyWithKey};
    use sha2::Sha256;
    use std::hash::{DefaultHasher, Hash, Hasher};
    use std::net::SocketAddr;

    const TOKEN_VALIDITY_SECONDS_PAST: u64 = 10;
    const TOKEN_VALIDITY_SECONDS_FUTURE: u64 = 1;

    const SPECIAL_NONCE_FOR_STATS: u64 = u64::MAX;

    #[derive(Debug, serde_derive::Deserialize, serde_derive::Serialize)]
    pub struct Request {
        pub nonce: Option<u64>,
    }

    #[derive(Debug, serde_derive::Deserialize, serde_derive::Serialize)]
    pub enum Reply {
        Registered,
        Retry(u64),
    }

    pub struct SecureKeepalives {
        key: Hmac<Sha256>,
        hasher: DefaultHasher,
    }

    pub enum ServerVerificationResult {
        Invalid,
        NeedsRetry(Vec<u8>),
        Accepted(Vec<u8>),
        StatsRequest,
    }

    pub enum ClientVerificationResult {
        Invalid,
        Resend(Vec<u8>),
        Ok,
    }

    pub const AUTH_SIGNATURE: &[u8] = b"eyJhbGciOiJIUzI1NiJ9.";

    impl SecureKeepalives {
        pub fn new(password: &str) -> Self {
            let password = password.as_bytes();
            let salt = b"udpexposer";
            let config = argon2::Config {
                variant: argon2::Variant::Argon2i,
                version: argon2::Version::Version13,
                mem_cost: 256,
                time_cost: 2,
                lanes: 2,
                secret: &[],
                ad: &[],
                hash_length: 32,
            };
            let hash = argon2::hash_raw(password, salt, &config).unwrap();

            let key: Hmac<Sha256> = Hmac::new_from_slice(&hash).unwrap();
            SecureKeepalives {
                key,
                hasher: Default::default(),
            }
        }

        pub fn sign(&self, msg: &impl serde::Serialize) -> String {
            msg.sign_with_key(&self.key).unwrap()
        }

        pub fn verify<T: for<'de> serde::Deserialize<'de>>(&self, msg: &[u8]) -> Option<T> {
            let Ok(msg) = std::str::from_utf8(msg) else {
                return None;
            };
            let Ok(ret): Result<T, _> = msg.verify_with_key(&self.key) else {
                return None;
            };
            Some(ret)
        }

        pub fn verify_request(
            &self,
            msg: &[u8],
            lax_mode: bool,
            from: SocketAddr,
        ) -> ServerVerificationResult {
            let time = crate::get_unixtime();
            let time_low = time.saturating_sub(TOKEN_VALIDITY_SECONDS_PAST);
            let time_high = time.saturating_add(TOKEN_VALIDITY_SECONDS_FUTURE);

            let Some(msg): Option<Request> = self.verify(msg) else {
                return ServerVerificationResult::Invalid;
            };

            if msg.nonce == Some(SPECIAL_NONCE_FOR_STATS) {
                return ServerVerificationResult::StatsRequest;
            }

            let nonce = msg.nonce;
            let mut h = self.hasher.clone();
            from.hash(&mut h);
            let addr_hash = h.finish();

            let accepted = lax_mode
                || if let Some(mut nonce) = nonce {
                    nonce ^= addr_hash;
                    if nonce >= time_low && nonce <= time_high {
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };

            if accepted {
                ServerVerificationResult::Accepted(self.sign(&Reply::Registered).into_bytes())
            } else {
                ServerVerificationResult::NeedsRetry(
                    self.sign(&Reply::Retry(time ^ addr_hash)).into_bytes(),
                )
            }
        }

        pub fn process_reply(&self, msg: &[u8]) -> ClientVerificationResult {
            let Some(msg): Option<Reply> = self.verify(msg) else {
                return ClientVerificationResult::Invalid;
            };

            match msg {
                Reply::Registered => ClientVerificationResult::Ok,
                Reply::Retry(x) => ClientVerificationResult::Resend(
                    self.sign(&Request { nonce: Some(x) }).into_bytes(),
                ),
            }
        }

        pub fn initial_client_request(&self) -> Vec<u8> {
            self.sign(&Request { nonce: None }).into_bytes()
        }

        pub fn stats_request(&self) -> Vec<u8> {
            self.sign(&Request {
                nonce: Some(SPECIAL_NONCE_FOR_STATS),
            })
            .into_bytes()
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let Args {
        listen_addr,
        local_connect_addr,
        server_addr,
        server_mode,
        max_clients,
        ping_interval_ms,
        password,
        dump_stats,
    } = argh::from_env();

    #[cfg(not(feature = "signed_keepalives"))]
    if password.is_some() {
        anyhow::bail!("--password support is not enabled at build time")
    }

    #[cfg(not(feature = "stats_display"))]
    if dump_stats {
        anyhow::bail!("--dump-stats support is not enabled at build time")
    }

    if dump_stats && password.is_none() {
        anyhow::bail!("--dump-stats does not work without --password")
    }
    if dump_stats && server_addr.is_none() {
        anyhow::bail!("--dump-stats does not work without --server-addr")
    }

    #[cfg(feature = "signed_keepalives")]
    let signer = password.map(|x| signed_keepalives::SecureKeepalives::new(&x));

    let main_socket = tokio::net::UdpSocket::bind(listen_addr).await?;
    let mut buf = [0u8; 2048];

    if server_mode {
        let mut stats = Stats::default();
        let mut client_address: Option<SocketAddr> = None;

        let mut seqn: u16 = 0;
        let mut lru = lru::LruCache::<SocketAddr, u16>::new(
            std::num::NonZeroUsize::new(max_clients).unwrap(),
        );
        let mut lru_rev = lru::LruCache::<u16, SocketAddr>::new(
            std::num::NonZeroUsize::new(max_clients).unwrap(),
        );

        loop {
            let Ok((n, from)) = main_socket.recv_from(&mut buf[2..]).await else {
                stats.err1 += 1;
                println!("Error receiving from the main socket");
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            };

            let mut is_keepalive = n == 0;

            let mut inhibit_wrong_channel_message = false;

            #[cfg(feature = "signed_keepalives")]
            if let Some(ref s) = signer {
                is_keepalive = false;
                let msg = &buf[2..][..n];
                if msg.starts_with(signed_keepalives::AUTH_SIGNATURE) {
                    stats.signed_looking += 1;
                    if client_address == Some(from) {
                        stats.last_ka_s = get_unixtime();
                        stats.refresh_address += 1;
                    }
                    match s.verify_request(msg, Some(from) == client_address, from) {
                        signed_keepalives::ServerVerificationResult::Invalid => {
                            stats.invalid_auths += 1;
                            println!("A client from {from} failed to authenticate");
                            inhibit_wrong_channel_message = true;
                        }
                        signed_keepalives::ServerVerificationResult::NeedsRetry(reply) => {
                            stats.auth_in_progress += 1;
                            println!("Authenticating: {from}");
                            if main_socket.send_to(&reply, from).await.is_err() {
                                println!("Error sending to the main socket to preauth client");
                                tokio::time::sleep(Duration::from_millis(5)).await;
                            }
                            continue;
                        }
                        signed_keepalives::ServerVerificationResult::Accepted(reply) => {
                            stats.auth_completeds += 1;
                            stats.last_ka_s = get_unixtime();
                            if client_address != Some(from) {
                                println!("New client address: {from}");
                                client_address = Some(from)
                            }

                            if main_socket.send_to(&reply, from).await.is_err() {
                                stats.err2 += 1;
                                println!("Error sending to the main socket to preauth client");
                                tokio::time::sleep(Duration::from_millis(5)).await;
                            }
                            continue;
                        }
                        signed_keepalives::ServerVerificationResult::StatsRequest => {
                            stats.stats_requests += 1;
                            #[cfg(feature = "stats")]
                            {
                                let config = bincode::config::legacy().with_big_endian();
                                let mut slice = [0u8; 256];
                                let n = bincode::encode_into_slice(&stats, &mut slice[..], config)
                                    .unwrap();
                                let b = &slice[..n];
                                if main_socket.send_to(&b, from).await.is_err() {
                                    println!("Error sending the main socket for stats request");
                                    tokio::time::sleep(Duration::from_millis(5)).await;
                                }
                            }
                            continue;
                        }
                    }
                }
            }

            if is_keepalive {
                stats.simple_keepalives += 1;
                stats.last_ka_s = get_unixtime();
                if client_address != Some(from) {
                    stats.simple_address_switches += 1;
                    println!("New client address: {from}");
                    client_address = Some(from)
                }
                continue;
            }

            if Some(from) == client_address {
                if n < 2 {
                    stats.dwarfs += 1;
                    println!("Too short datagram from client");
                    continue;
                }

                let channel_id: [u8; 2] = buf[2..4].try_into().unwrap();
                let channel_id = u16::from_be_bytes(channel_id);

                let Some(&addr) = lru_rev.peek(&channel_id) else {
                    if !inhibit_wrong_channel_message {
                        stats.ch_not_founds += 1;
                        println!("Failed to find channel {channel_id}");
                    }
                    continue;
                };

                #[cfg(feature = "stats")]
                {
                    stats.from_client_msgs += 1;
                    stats.from_client_bytes += n as u64 - 2;
                    stats.last_client_s = get_unixtime();
                }

                if main_socket.send_to(&buf[4..(n + 2)], addr).await.is_err() {
                    stats.err3 += 1;
                    println!("Error sending to the main socket to connectee");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            } else {
                let Some(client_address) = client_address else {
                    stats.dropped_no_client_address += 1;
                    continue;
                };

                let &channel_id = lru.get_or_insert(from, || {
                    stats.new_connectees += 1;
                    seqn += 1;
                    println!("Connectee seqn {seqn} from {from}");

                    lru_rev.push(seqn, from);

                    seqn
                });

                buf[0..2].copy_from_slice(&channel_id.to_be_bytes());

                #[cfg(feature = "stats")]
                {
                    stats.from_connectee_msgs += 1;
                    stats.from_connectee_bytes += n as u64;
                    stats.last_connectee_s = get_unixtime();
                }

                if main_socket
                    .send_to(&buf[..(2 + n)], client_address)
                    .await
                    .is_err()
                {
                    stats.err4 += 1;
                    println!("Error sending to the main socket to client");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            }
        }
    } else if let (Some(server_addr), true) = (server_addr, dump_stats) {
        #[cfg(all(feature = "signed_keepalives", feature = "stats_display"))]
        {
            let msg = signer.unwrap().stats_request();

            if main_socket.connect(server_addr).await.is_err() {
                anyhow::bail!("Failed to connect the socket to server address");
            }

            if main_socket.send(&msg).await.is_err() {
                anyhow::bail!("Failed to send a stats request to server address");
            }

            let mut buf = [0u8; 256];

            let Ok(n) = main_socket.recv(&mut buf[..]).await else {
                anyhow::bail!("Failed to receive a replay from server");
            };

            let b = &buf[..n];

            let config = bincode::config::legacy().with_big_endian();
            let (msg, _): (Stats, _) = bincode::decode_from_slice(b, config).unwrap();

            serde_json::ser::to_writer(std::io::stdout(), &msg).unwrap();
        }

        Ok(())
    } else if let (Some(local_connect_addr), Some(server_addr)) = (local_connect_addr, server_addr)
    {
        // Client mode

        let main_socket = Arc::new(main_socket);

        // channel number should already be prepended in those buffers
        //let (tx,mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(2);

        let neutral_local_addr = if local_connect_addr.is_ipv4() {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        };

        let mut lru = lru::LruCache::<u16, Sender<Box<[u8]>>>::new(
            std::num::NonZeroUsize::new(max_clients).unwrap(),
        );

        let mut pinger = tokio::time::interval(Duration::from_millis(ping_interval_ms));
        pinger.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        enum Outcome {
            Tick,
            FromMainSocket(std::io::Result<(usize, SocketAddr)>),
            //FromActor(Option<DatagramFromLocal>),
        }

        #[cfg(feature = "signed_keepalives")]
        let mut announced_registration = false;

        loop {
            let ret: Outcome = tokio::select! {
                biased;
                _ret = pinger.tick() => {
                    Outcome::Tick
                }

                ret = main_socket.recv_from(&mut buf[..]) => {
                    Outcome::FromMainSocket(ret)
                }
                // ret = rx.recv() => {
                //     Outcome::FromActor(ret)
                // }
            };

            match ret {
                Outcome::Tick => {
                    let mut msg: &[u8] = b"";
                    let msg_buf: Vec<u8>;
                    #[cfg(feature = "signed_keepalives")]
                    if let Some(ref s) = signer {
                        msg_buf = s.initial_client_request();
                        msg = &msg_buf;
                    }
                    if main_socket.send_to(msg, server_addr).await.is_err() {
                        println!("Failed to send a keepalive to server address");
                    }
                }
                Outcome::FromMainSocket(Err(e)) => {
                    println!("Failed to receive from the main socket: {e}");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                Outcome::FromMainSocket(Ok((n, _from))) => {
                    if n <= 2 {
                        println!("Datagram from server is too small");
                        continue;
                    }

                    #[cfg(feature = "signed_keepalives")]
                    if let Some(ref s) = signer {
                        if buf.starts_with(signed_keepalives::AUTH_SIGNATURE) {
                            match s.process_reply(&buf[0..n]) {
                                signed_keepalives::ClientVerificationResult::Invalid => {}
                                signed_keepalives::ClientVerificationResult::Resend(vec) => {
                                    if main_socket.send_to(&vec, server_addr).await.is_err() {
                                        println!("Failed to send a keepalive to server address");
                                    } else {
                                        if !announced_registration {
                                            println!("Received a reply from server");
                                        }
                                    }
                                    continue;
                                }
                                signed_keepalives::ClientVerificationResult::Ok => {
                                    if !announced_registration {
                                        println!("Authenticated");
                                        announced_registration = true;
                                    }
                                    continue;
                                }
                            }
                        }
                    }

                    let channel_id: [u8; 2] = buf[0..2].try_into().unwrap();
                    let channel_id = u16::from_be_bytes(channel_id);

                    let conn: &mut Sender<Box<[u8]>> = lru.get_or_insert_mut(channel_id, || {
                        println!("New incoming channel {channel_id}");

                        let main_socket = main_socket.clone();
                        let (tx, mut rx) = tokio::sync::mpsc::channel(2);

                        tokio::spawn(async move {
                            let u = tokio::net::UdpSocket::bind(neutral_local_addr).await?;
                            let mut buf2 = [0u8; 2048];

                            enum Outcome2 {
                                FromMpsc(Option<Box<[u8]>>),
                                FromSocket(std::io::Result<(usize, SocketAddr)>),
                            }

                            loop {
                                let ret = tokio::select! {
                                    biased;
                                    ret = rx.recv() => {
                                        Outcome2::FromMpsc(ret)
                                    }
                                    ret = u.recv_from(&mut buf2[2..]) => {
                                        Outcome2::FromSocket(ret)
                                    }
                                };

                                match ret {
                                    Outcome2::FromMpsc(None) => break,
                                    Outcome2::FromMpsc(Some(x)) => {
                                        if u.send_to(&*x, local_connect_addr).await.is_err() {
                                            println!("Error sending to local addr");
                                        }
                                    }
                                    Outcome2::FromSocket(Err(e)) => {
                                        println!("Error receiving from worker socket: {e}");
                                    }
                                    Outcome2::FromSocket(Ok((n, from))) => {
                                        if from != local_connect_addr {
                                            println!(
                                                "Foreign incoming address on worker socket: {from}"
                                            );
                                            continue;
                                        }

                                        buf2[0..2].copy_from_slice(&channel_id.to_be_bytes());

                                        if main_socket
                                            .send_to(&buf2[0..(n + 2)], server_addr)
                                            .await
                                            .is_err()
                                        {
                                            println!("Error sending to server addr {server_addr}");
                                        }
                                    }
                                }
                            }

                            println!("Finished serving channel {channel_id}");

                            Ok::<_, anyhow::Error>(())
                        });
                        tx
                    });

                    //println!("Datafrom of length {} from {channel_id}", n-2);
                    conn.send(buf[2..n].into()).await?;
                }
            }
        }
    } else {
        anyhow::bail!("Invalid options: either -s or both -c and -a should be specified")
    }
}
