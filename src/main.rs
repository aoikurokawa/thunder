use std::{
    io::{self, Read},
    thread,
};

fn main() -> io::Result<()> {
    let mut i = thunder::Interface::new()?;
    let mut l1 = i.bind(9000)?;

    let jh1 = thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            eprintln!("got connection on 9000");

            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            eprintln!("read data");
            assert_eq!(n, 0);
        }
    });

    jh1.join().unwrap();

    Ok(())
}
