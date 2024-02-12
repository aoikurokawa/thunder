use std::{
    cmp::Ordering,
    io::{self, Write},
};

enum State {
    // Listen,
    SynRcvd,
    Estab,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
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
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: u32,
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
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];

        // only expected SYN packet
        if !tcph.syn() {
            return Ok(None);
        }

        let iss = 0;
        let wnd = 10;
        let mut c = Connection {
            state: State::SynRcvd,
            // decide on stuff we're sending them
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd,
                up: false,

                wl1: 0,
                wl2: 0,
            },
            // keep track of sender info
            recv: RecvSequenceSpace {
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
                irs: tcph.sequence_number(),
            },
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpNumber::TCP,
                iph.destination_addr().octets(),
                iph.source_addr().octets(),
            )
            .expect("construct Ipv4 header"),
            tcp: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),
        };

        // need to establish a connection
        c.tcp.syn = true;
        c.tcp.ack = true;

        c.write(nic, &[])?;

        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];

        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;
        self.ip
            .set_payload_len(self.tcp.header_len() + payload.len())
            .expect("failed to set payload length");

        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten)?;
        self.tcp.write(&mut unwritten)?;
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
        nic.send(&buf[..buf.len() - unwritten])?;

        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;

        Ok(())
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // first, check that sequence number are valid (RFC 793 S3.3)
        //
        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        // but remember wrapping!
        //
        let ackn = tcph.acknowledgment_number();
        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            if !self.state.is_synchronized() {
                // according to Reset Generation, we should send RST
                self.send_rst(nic);
            }
            return Ok(());
        }

        // valid segment check. okay if it acks at least one byte, which means that at least one of
        // the following is true:
        //
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        //
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        }
        if tcph.syn() {
            slen += 1;
        }
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        if slen == 0 {
            if self.recv.wnd == 0 {
                if seqn == self.recv.nxt {
                    return Ok(());
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn + slen - 1, wend)
            {
                return Ok(());
            }
        }

        match self.state {
            State::SynRcvd => {
                // expect to get an ACK for our SYN
                if !tcph.ack() {
                    return Ok(());
                }

                self.state = State::Estab;
            }
            State::Estab => {
                //
                unimplemented!()
            }
        }
        Ok(())
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    match start.cmp(&x) {
        Ordering::Equal => return false,
        Ordering::Less => {
            if end >= start && end <= x {
                return false;
            }
        }
        Ordering::Greater => {
            if end < start && end < x {
            } else {
                return false;
            }
        }
    }

    true
}
