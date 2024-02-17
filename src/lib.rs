use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    io,
    net::Ipv4Addr,
    sync::{mpsc, Arc, Mutex},
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

type InterfaceHandle = Arc<Mutex<ConnectionManager>>;

#[derive(Default)]
struct ConnectionManager {
    connections: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

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
    ih: InterfaceHandle,
    jh: thread::JoinHandle<()>,
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;

        let cm: InterfaceHandle = Arc::default();

        let jh = {
            let cm = cm.clone();
            thread::spawn(move || {
                let nic = nic;
                let cm = cm;
                let buf = [0u8; 1504];

                // do the stuff that main does
            })
        };

        Ok(Self { ih: cm, jh })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<tcp_listener::TcpListener> {
        let mut cm = self.ih.lock().unwrap();
        match cm.pending.entry(port) {
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "port already bound",
                ));
            }
            Entry::Vacant(v) => {
                v.insert(VecDeque::new());
            }
        }
        drop(cm);
        Ok(tcp_listener::TcpListener(port, self.ih.clone()))
    }
}
