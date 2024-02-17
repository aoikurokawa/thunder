use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::Ipv4Addr,
    sync::mpsc,
    thread,
};

mod tcp;
mod tcp_listener;
mod tcp_stream;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

type InterfaceHandle = mpsc::Sender<InterfaceRequest>;

enum InterfaceRequest {
    Write {
        quad: Quad,
        bytes: Vec<u8>,
        ack: mpsc::Sender<usize>,
    },
    Flush {
        quad: Quad,
        ack: mpsc::Sender<usize>,
    },
    Bind {
        port: u16,
        ack: mpsc::Sender<()>,
    },
    Unbind {},
    Read {
        quad: Quad,
        max_length: usize,
        read: mpsc::Sender<Vec<u8>>,
    },
    Accept {
        port: u16,
        read: mpsc::Sender<Quad>,
    },
}

pub struct Interface {
    tx: InterfaceHandle,
    jh: thread::JoinHandle<()>,
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let cm = ConnectionManager {
            connections: Default::default(),
            nic: tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?,
            buf: [0u8; 1504],
        };

        let (tx, rx) = mpsc::channel();
        let jh = thread::spawn(move || cm.run_on(rx));

        Ok(Self { tx, jh })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<tcp_listener::TcpListener> {
        let (ack, rx) = mpsc::channel();
        self.tx
            .send(InterfaceRequest::Bind { port, ack })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        rx.recv().unwrap();
        Ok(tcp_listener::TcpListener(port, self.tx.clone()))
    }
}

struct ConnectionManager {
    connections: HashMap<Quad, tcp::Connection>,
    nic: tun_tap::Iface,
    buf: [u8; 1504],
}

impl ConnectionManager {
    pub fn run_on(self, rx: mpsc::Receiver<InterfaceRequest>) {
        // main event loop for packet processing
        for req in rx {}
    }
}
