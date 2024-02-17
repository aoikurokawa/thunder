use std::{io, sync::mpsc};

use crate::{
    tcp_stream::{self},
    InterfaceHandle, InterfaceRequest,
};

pub struct TcpListener(pub u16, pub InterfaceHandle);

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<tcp_stream::TcpStream> {
        let (read, rx) = mpsc::channel();
        self.1
            .send(InterfaceRequest::Accept { port: self.0, read })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let quad = rx.recv().unwrap();
        Ok(tcp_stream::TcpStream(quad, self.1.clone()))
    }
}
