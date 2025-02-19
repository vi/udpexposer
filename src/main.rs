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
    } = argh::from_env();

    let main_socket = tokio::net::UdpSocket::bind(listen_addr).await?;
    let mut buf = [0u8; 2048];

    if server_mode {
        let mut client_address: Option<SocketAddr> = None;

        let mut seqn: u16 = 0;
        let mut lru = lru::LruCache::<SocketAddr, u16>::new(
            std::num::NonZeroUsize::new(max_clients).unwrap(),
        );

        loop {
            let Ok((n, from)) = main_socket.recv_from(&mut buf[2..]).await else {
                println!("Error receiving from the main socket");
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            };

            if n == 0 {
                if client_address != Some(from) {
                    println!("New client address: {from}");
                    client_address = Some(from)
                }
                continue;
            }

            if Some(from) == client_address {
                if n < 2 {
                    println!("Too short datagram from client");
                    continue;
                }

                let channel_id: [u8; 2] = buf[2..4].try_into().unwrap();
                let channel_id = u16::from_be_bytes(channel_id);

                // FIXME: inefficient iteration
                let Some((&addr, _)) = lru.iter().find(|(_, v)| **v == channel_id) else {
                    println!("Failed to find channel {channel_id}");
                    continue;
                };

                if main_socket.send_to(&buf[4..(n+2)], addr).await.is_err() {
                    println!("Error sending to the main socket to client");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            } else {
                let Some(client_address) = client_address else {
                    continue;
                };

                let &channel_id = lru.get_or_insert(from, || {
                    seqn += 1;
                    println!("Connectee seqn {seqn} from {from}");
                    seqn
                });

                buf[0..2].copy_from_slice(&channel_id.to_be_bytes());

                if main_socket
                    .send_to(&buf[..(2 + n)], client_address)
                    .await
                    .is_err()
                {
                    println!("Error sending to the main socket to connectee");
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            }
        }
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
                    if main_socket.send_to(b"", server_addr).await.is_err() {
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
                        println!("Datafram from server too small");
                        continue;
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
                                    Outcome2::FromSocket(Ok((n,from))) => {
                                        if from != local_connect_addr {
                                            println!("Foreign incoming address on worker socket: {from}");
                                            continue;
                                        }

                                        buf2[0..2].copy_from_slice(&channel_id.to_be_bytes());

                                        if main_socket.send_to(&buf2[0..(n+2)], server_addr).await.is_err() {
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
