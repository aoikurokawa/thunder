use std::io;

use crate::{
    tcp_stream::{self},
    InterfaceHandle,
};

pub struct TcpListener {
    pub port: u16,
    pub h: InterfaceHandle,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let mut cm = self.h.manager.lock().unwrap();
        let pending = cm
            .pending
            .remove(&self.port)
            .expect("port closed while listener still active");

        for _quad in pending {
            unimplemented!()
        }
    }
}

impl TcpListener {
    pub fn accept(&mut self) -> io::Result<tcp_stream::TcpStream> {
        let mut cm = self.h.manager.lock().unwrap();

        loop {
            if let Some(quad) = cm
                .pending
                .get_mut(&self.port)
                .expect("port closed while listener still active")
                .pop_front()
            {
                return Ok(tcp_stream::TcpStream {
                    quad,
                    h: self.h.clone(),
                });
            };
            cm = self.h.pending_var.wait(cm).unwrap();
        }
    }
}
