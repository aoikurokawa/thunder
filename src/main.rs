use std::{
    io::{self, Read, Write},
    thread,
};

fn main() -> io::Result<()> {
    let mut i = thunder::Interface::new()?;
    let mut listener = i.bind(9000)?;

    while let Ok(mut stream) = listener.accept() {
        thread::spawn(move || {
            eprintln!("got connection!");
            stream.write(b"hello from thunder").unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            loop {
                let mut buf = [0u8; 512];
                let n = stream.read(&mut buf).unwrap();
                eprintln!("read {}bytes of data", n);
                if n == 0 {
                    eprintln!("no more data");
                    break;
                } else {
                    println!("{}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        });
    }

    Ok(())
}
