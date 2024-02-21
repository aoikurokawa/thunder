use std::{
    io::{self, Read, Write},
    net::Shutdown,
};

use crate::{InterfaceHandle, Quad, SENDQUEUE_SIZE};

pub struct TcpStream {
    pub quad: Quad,
    pub h: InterfaceHandle,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let _cm = self.h.manager.lock().unwrap();

        // TODO: send FIN on cm.connections[quad]
        // TODO: _eventually_ remove self.quad from cm.connections
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cm = self.h.manager.lock().unwrap();
        loop {
            let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "stream was terminated unexpectedly",
                )
            })?;

            if c.is_rcv_closed() && c.incoming.is_empty() {
                // no more data to read, and no need to block
                return Ok(0);
            }

            if !c.incoming.is_empty() {
                let mut nread = 0;
                let (head, tail) = c.incoming.as_slices();

                let hread = std::cmp::min(buf.len(), head.len());
                buf[..hread].copy_from_slice(&head[..hread]);
                nread += hread;

                let tread = std::cmp::min(buf.len() - nread, tail.len());
                buf[hread..(hread + tread)].copy_from_slice(&tail[..tread]);
                nread += tread;

                drop(c.incoming.drain(..nread));

                return Ok(nread);
            }

            cm = self.h.rcv_var.wait(cm).unwrap();
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.len() > SENDQUEUE_SIZE {
            // TODO: block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes buffered",
            ));
        }

        let nwrite = std::cmp::min(buf.len(), SENDQUEUE_SIZE - c.unacked.len());
        c.unacked.extend(&buf[..nwrite]);

        Ok(nwrite)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpectedly",
            )
        })?;

        if c.unacked.is_empty() {
            Ok(())
        } else {
            // TODO: block
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "too many bytes buffered",
            ))
        }
    }
}

impl TcpStream {
    pub fn shutdown(&mut self, _how: Shutdown) -> io::Result<()> {
        let mut cm = self.h.manager.lock().unwrap();
        let c = cm.connections.get_mut(&mut self.quad).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream was terminated unexpextedly",
            )
        })?;

        c.close()
    }
}
