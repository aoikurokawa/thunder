use std::{
    io::{self, Read, Write},
    sync::mpsc,
};

use crate::{InterfaceHandle, InterfaceRequest, Quad};

pub struct TcpStream(pub Quad, pub InterfaceHandle);

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (read, rx) = mpsc::channel();
        self.1
            .send(InterfaceRequest::Read {
                quad: self.0,
                max_length: buf.len(),
                read,
            })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let bytes = rx.recv().unwrap();
        assert!(bytes.len() <= buf.len());
        buf.copy_from_slice(&bytes[..]);
        Ok(bytes.len())
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (ack, rx) = mpsc::channel();
        self.1
            .send(InterfaceRequest::Write {
                quad: self.0,
                bytes: Vec::from(buf),
                ack,
            })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let n = rx.recv().unwrap();
        assert!(n <= buf.len());
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        let (ack, rx) = mpsc::channel();
        self.1
            .send(InterfaceRequest::Flush { quad: self.0, ack })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        rx.recv().unwrap();
        Ok(())
    }
}
