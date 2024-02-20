use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, Write},
    ops::Mul,
    time,
};

use bitflags::bitflags;

bitflags! {
    pub struct Available: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

pub enum State {
    // Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 | State::TimeWait => true,
        }
    }
}

pub struct Connection {
    pub state: State,
    pub send: SendSequenceSpace,
    pub recv: RecvSequenceSpace,
    pub ip: etherparse::Ipv4Header,
    pub tcp: etherparse::TcpHeader,
    pub timers: Timers,

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,
    pub(crate) closed: bool,
    pub(crate) closed_at: Option<u32>,
}

struct Timers {
    send_times: BTreeMap<u32, time::Instant>,
    srtt: time::Duration,
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
pub struct SendSequenceSpace {
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
pub struct RecvSequenceSpace {
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
        // only expected SYN packet
        if !tcph.syn() {
            return Ok(None);
        }

        let iss = 0;
        let wnd = 1024;
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
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },
            tcp: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpNumber::TCP,
                iph.destination_addr().octets(),
                iph.source_addr().octets(),
            )
            .expect("construct Ipv4 header"),

            incoming: Default::default(),
            unacked: Default::default(),
            timers: Timers {
                send_times: BTreeMap::default(),
                srtt: time::Duration::from_secs(1 * 60),
            },
            closed: false,
            closed_at: None,
        };

        // need to establish a connection
        c.tcp.syn = true;
        c.tcp.ack = true;

        c.write(nic, c.send.nxt, &[], &[], 0)?;

        Ok(Some(c))
    }

    fn write(
        &mut self,
        nic: &mut tun_tap::Iface,
        seq: u32,
        payload1: &[u8],
        payload2: &[u8],
        limit: usize,
    ) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        // self.tcp.sequence_number = self.send.nxt;
        self.tcp.sequence_number = seq;
        self.tcp.acknowledgment_number = self.recv.nxt;

        let max_data = std::cmp::min(limit, payload1.len() + payload2.len());
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() + self.ip.header_len() + max_data,
        );
        self.ip
            .set_payload_len(size - self.ip.header_len())
            .expect("failed to set payload length");

        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("failed to compute checksum");

        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten)?;
        self.tcp.write(&mut unwritten)?;
        let payload_bytes = {
            let mut written = 0;
            let mut limit = max_data;

            let mut p1l = std::cmp::min(limit, payload1.len());
            written += unwritten.write(&payload1[..p1l])?;
            limit -= written;

            let p2l = std::cmp::min(limit, payload2.len());
            written += unwritten.write(&payload2[..p2l])?;

            written
        };
        let unwritten = unwritten.len();
        let mut next_seq = seq.wrapping_add(payload_bytes as u32);

        if self.tcp.syn {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.fin = false;
        }

        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }
        nic.send(&buf[..buf.len() - unwritten])?;

        self.timers.send_times.insert(seq, time::Instant::now());

        Ok(payload_bytes)
    }

    // pub fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
    //     self.tcp.rst = true;
    //     self.tcp.sequence_number = 0;
    //     self.tcp.acknowledgment_number = 0;

    //     self.write(nic, self.send.nxt, &[], &[], 0)?;

    //     Ok(())
    // }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        _iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Available> {
        // first, check that sequence number are valid (RFC 793 S3.3)
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        }
        if tcph.syn() {
            slen += 1;
        }
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let okay = if slen == 0 {
            if self.recv.wnd == 0 {
                if seqn == self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                false
            } else {
                true
            }
        };

        if !okay {
            self.write(nic, self.send.nxt, &[], &[], 0)?;
            return Ok(self.availability());
        }

        if !tcph.ack() {
            if tcph.syn() {
                // got SYN part of initial handshake
                assert!(data.is_empty());
                self.recv.nxt = seqn.wrapping_add(1);
            }
            return Ok(self.availability());
        }

        let ackn = tcph.acknowledgment_number();
        if let State::SynRcvd = self.state {
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                self.state = State::Estab;
            } else {
                // TODO: RST:
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                self.send.una = ackn;
            }

            // TODO: prune self.unacked
            // TODO: if unacked empty and waiting flush, notify

            // FIXME: we don't support Write yet, so immediatedly send EOF
            if let State::Estab = self.state {
                // TODO: needs to be stored in the retransmission queue!
                self.tcp.fin = true;
                // self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
            // TODO: update window
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // our FIN has been ACKed!
                self.state = State::FinWait2;
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            let mut unread_data_at = (self.recv.nxt - seqn) as usize;
            if unread_data_at > data.len() {
                // we must have received a re-transmitted FIN that we have already senn
                // nxt points to beyond the fin, but the fin is not in data!
                assert_eq!(unread_data_at, data.len() + 1);
                unread_data_at = 0;
            }
            self.incoming.extend(&data[unread_data_at..]);

            self.recv.nxt = seqn
                .wrapping_add(data.len() as u32)
                .wrapping_add(if tcph.fin() { 1 } else { 0 });

            // Send an acknowledgement of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            // TODO: maybe just tick to piggyback ack on data?
            self.write(nic, self.send.nxt, &[], &[], 0)?;
        }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    // we're done with the connnection
                    self.write(nic, self.send.nxt, &[], &[], 0)?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }

        Ok(self.availability())
    }

    pub(crate) fn is_rcv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            true
        } else {
            false
        }
    }

    fn availability(&self) -> Available {
        let mut a = Available::empty();
        if self.is_rcv_closed() || !self.incoming.is_empty() {
            a |= Available::READ;
        }

        a
    }

    pub(crate) fn on_tick(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        let nunacked = self.send.nxt.wrapping_sub(self.send.una) as usize;
        let unsent = self.unacked.len() - nunacked;

        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|x| time::Instant::elapsed(x.1));

        let should_retransmit = if let Some(waited_for) = waited_for {
            waited_for > time::Duration::from_secs(1)
                && waited_for.as_secs_f32() > 1.5 * self.timers.srtt.as_secs_f32()
        } else {
            false
        };

        if should_retransmit {
            // we should retransmit things
            let resend = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);
            if resend < self.send.wnd as u32 && self.closed {
                // can include the FIN?
                self.tcp.fin = true;
            }
            let (h, t) = self.unacked.as_slices();
            self.write(nic, self.send.una, h, t, resend as usize)?;
            self.send.nxt = self.send.una.wrapping_add(resend);
        } else {
            // we should send new data if we have new data and space in the window
            if unsent == 0 && self.closed_at.is_some() {
                return Ok(());
            }

            let allowed = self.send.wnd as usize - nunacked;
            if allowed == 0 {
                return Ok(());
            }

            let send = std::cmp::min(unsent, allowed);
            if send < allowed && self.closed && self.closed_at.is_none() {
                self.tcp.fin = true;
                self.closed_at = Some(self.send.nxt.wrapping_add(unsent as u32));
            }
            let (mut h, mut t) = self.unacked.as_slices();
            // we want self.unacked[nunacked..]
            if h.len() >= nunacked {
                h = &h[nunacked as usize..];
            } else {
                let skipped = h.len();
                h = &[];
                t = &t[(nunacked - skipped)..];
            }

            self.write(nic, self.send.nxt, h, t, send)?;
        }

        // decide if it needs to send something send it
        Ok(())
    }

    pub(crate) fn close(&self) -> io::Result<()> {
        self.closed = true;

        match self.state {
            State::SynRcvd | State::Estab => {
                self.state = State::FinWait1;
            }
            State::FinWait1 | State::FinWait2 => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "already closed",
                ));
            }
        }

        Ok(())
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    //  TCP datermines if a data segement is "old" or "new" by testing
    //  whether its sequence number is within 2 ** 31 bytes of the left edge
    //  of the window. and if it is not, discarding the data as "old". To insure that new data is
    //  never mistakenly considered old and vice-versa. the left edge of the sender's window has to
    //  be at most 2 ** 31 away  from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > 2 ^ 31
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
