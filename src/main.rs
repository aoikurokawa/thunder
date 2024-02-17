use std::{collections::hash_map::Entry, io};

fn main() -> io::Result<()> {
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
                        match connections.entry(Quad {
                            src: (src, tcph.source_port()),
                            dst: (dst, tcph.destination_port()),
                        }) {
                            Entry::Occupied(mut c) => {
                                c.get_mut()
                                    .on_packet(&mut nic, iph, tcph, &buf[datai..nbytes])?;
                            }
                            Entry::Vacant(e) => {
                                if let Some(c) = Connection::accept(&mut nic, iph, tcph)? {
                                    e.insert(c);
                                };
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet: {e}");
                    }
                }
            }
            Err(e) => {
                eprintln!("ignoring weird packet: {e}");
            }
        }
    }
}
