use std::{
    collections::HashMap,
    io::{self, Read, Write},
};

use etherparse::err::tcp;

pub struct Interface {
    connections: : HashMap<Quad, tcp::Connection>,
    nic: tun_tap::Iface,
    buf: [u8; 1504],
}

impl Interface {
    pub fn new() -> io::Result<Self> {

        Ok(Self {
            connection: Default::default(),
            nic: tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?,
            buf: [0u8; 1504],
        })
    }

    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        unimplemented!()
    }
}

pub struct TcpStream {}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unimplemented!()
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unimplemented!()
    }

    fn flush(&mut self) -> io::Result<()> {
        unimplemented!()
    }
}

pub struct TcpListener {}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<TcpStream> {
        unimplemented!()
    }
}
