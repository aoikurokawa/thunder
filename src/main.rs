use std::io;

fn main() -> io::Result<()> {
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];

    let nbytes = nic.recv(&mut buf[..])?;
    let flags = u16::from_be_bytes([buf[0], buf[1]]);
    let proto = u16::from_be_bytes([buf[2], buf[3]]);

    eprintln!("Flags: {flags}, Proto: {proto}");
    eprintln!("read {} bytes: {:x?}", nbytes - 4, &buf[4..nbytes]);

    Ok(())
}
