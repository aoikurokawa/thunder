use std::io;

use crate::{
    tcp_stream::{self},
    InterfaceHandle,
};

pub struct TcpListener(pub u16, pub InterfaceHandle);

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<tcp_stream::TcpStream> {
        let port = &self.0;
        let cm = self.1.lock().unwrap();
        if let Some(quad) = cm
            .pending
            .get(port)
            .expect("port closed while listener still active")
            .pop_front()
        {
            Ok(tcp_stream::TcpStream(quad, self.1.clone()))
        } else {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no connection available to accept",
            ))
        }
    }
}
