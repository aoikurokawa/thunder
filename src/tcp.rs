use std::{collections::BTreeMap, time};

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
    pub fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 | State::TimeWait => true,
        }
    }
}

pub struct Timers {
    pub send_times: BTreeMap<u32, time::Instant>,
    pub srtt: f64,
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
    pub una: u32,
    /// send next
    pub nxt: u32,
    /// send window
    pub wnd: u16,
    /// send urgent pointer
    pub up: bool,
    /// segment sequence number used for last window update
    pub wl1: usize,
    /// segment acknowledgment number used for last window update
    pub wl2: usize,
    /// initial send sequence number
    pub iss: u32,
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
    pub nxt: u32,
    /// receive window
    pub wnd: u16,
    /// receive urgent pointer
    pub up: bool,
    /// initial receive sequence number
    pub irs: u32,
}
