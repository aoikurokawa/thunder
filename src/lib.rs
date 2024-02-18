use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    io,
    net::Ipv4Addr,
    sync::{mpsc, Arc, Condvar, Mutex},
    thread,
};

mod tcp;
mod tcp_listener;
mod tcp_stream;

const SENDQUEUE_SIZE: usize = 1024;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

#[derive(Default)]
pub struct Foobar {
    manager: Mutex<ConnectionManager>,
    pending_var: Condvar,
    rcv_var: Condvar,
}

type InterfaceHandle = Arc<Foobar>;

#[derive(Default)]
pub struct Pending {
    pub quads: VecDeque<Quad>,
    pub var: Condvar,
}

#[derive(Default)]
pub struct ConnectionManager {
    terminate: bool,
    connections: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

pub enum InterfaceRequest {
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
    ih: Option<InterfaceHandle>,
    jh: Option<thread::JoinHandle<io::Result<()>>>,
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.ih.as_mut().unwrap().manager.lock().unwrap().terminate = true;

        drop(self.ih.take());
        self.jh
            .take()
            .expect("interface dropped more than once")
            .join()
            .unwrap()
            .unwrap();
    }
}

impl Interface {
    pub fn new() -> io::Result<Self> {
        let mut nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;

        let ih: InterfaceHandle = Arc::default();

        let jh = {
            let ih = ih.clone();
            thread::spawn(move || packet_loop(&mut nic, ih))
        };

        Ok(Self {
            ih: Some(ih),
            jh: Some(jh),
        })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<tcp_listener::TcpListener> {
        let mut cm = self.ih.as_mut().unwrap().manager.lock().unwrap();
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
        Ok(tcp_listener::TcpListener {
            port,
            h: self.ih.as_mut().unwrap().clone(),
        })
    }
}

fn packet_loop(nic: &mut tun_tap::Iface, ih: InterfaceHandle) -> io::Result<()> {
    let mut buf = [0u8; 1504];

    loop {
        let nbytes = nic.recv(&mut buf[..])?;

        // let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);

        // if eth_proto != 0x0800 {
        //     // no IPV4
        //     continue;
        // }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                if iph.protocol().0 != 0x06 {
                    eprint!("BAD PROTOCOL");
                    // not tcp
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[iph.slice().len()..nbytes]) {
                    Ok(tcph) => {
                        let datai = iph.slice().len() + tcph.slice().len();
                        let mut cmg = ih.manager.lock().unwrap();
                        let cm = &mut *cmg;
                        let quad = Quad {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        };
                        match cm.connections.entry(quad) {
                            Entry::Occupied(mut c) => {
                                let a =
                                    c.get_mut().on_packet(nic, iph, tcph, &buf[datai..nbytes])?;

                                // TODO: compare before/after
                                drop(cmg);
                                if a.contains(tcp::Available::READ) {
                                    ih.rcv_var.notify_all();
                                }

                                if a.contains(tcp::Available::WRITE) {
                                    // TODO: ih.snd_var.notify_all();
                                }
                            }
                            Entry::Vacant(e) => {
                                if let Some(pending) = cm.pending.get_mut(&tcph.destination_port())
                                {
                                    if let Some(c) = tcp::Connection::accept(nic, iph, tcph)? {
                                        e.insert(c);
                                        pending.push_back(quad);
                                        drop(cmg);
                                        ih.pending_var.notify_all();
                                        // TODO: wake up pending accept()
                                    };
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet: {e}");
                    }
                }
            }
            Err(_e) => {
                // eprintln!("ignoring weird packet: {e}");
            }
        }
    }
}
