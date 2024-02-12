use std::io;

enum State {
    Closed,
    Listen,
    // SynRcvd,
    // Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
}

/// State of Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```
///      1         2          3          4
/// ----------|----------|----------|----------
///        SND.UNA    SND.NXT    SND.UNA
///                             +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
struct SendSequenceSpace {
    /// send unacknowledged
    una: usize,
    /// send next
    nxt: usize,
    /// send window
    wnd: usize,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: usize,
}

/// State of Receive Sequence Space (RFC 793 S3.2 F5)
///
/// ```
///    1          2          3
///----------|----------|----------
///       RCV.NXT    RCV.NXT
///                 +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
struct RecvSequenceSpace {
    /// receive next
    nxt: usize,
    /// receive window
    wnd: usize,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: usize,
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            state: State::Listen,
        }
    }
}

impl Connection {
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];

        match self.state {
            State::Closed => {
                return Ok(0);
            }
            State::Listen => {
                if !tcph.syn() {
                    // only expected SYN packet
                    return Ok(0);
                }

                // need to establish a connection
                let mut syn_ack =
                    etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), 0, 0);
                syn_ack.syn = true;
                syn_ack.ack = true;
                let ip = etherparse::Ipv4Header::new(
                    syn_ack.header_len_u16(),
                    64,
                    etherparse::IpNumber::TCP,
                    iph.destination_addr().octets(),
                    iph.source_addr().octets(),
                )
                .expect("construct Ipv4 header");

                // Write out the headers
                let unwritten = {
                    let mut unwritten = &mut buf[..];
                    ip.write(&mut unwritten)?;
                    syn_ack.write(&mut unwritten)?;
                    unwritten.len()
                };

                Ok(nic.send(&buf[..unwritten])?)
            }
        }
        // eprintln!(
        //     "{}:{} -> {}:{} {}b of tcp",
        //     iph.source_addr(),
        //     tcph.source_port(),
        //     iph.destination_addr(),
        //     tcph.source_port(),
        //     data.len(),
        // );

        // Ok(())
    }
}
