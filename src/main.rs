use std::{io, thread};

fn main() -> io::Result<()> {
    let mut i = thunder::Interface::new()?;
    let mut l1 = i.bind(9000)?;

    let jh1 = thread::spawn(move || {
        while let Ok(stream) = l1.accept() {
            eprintln!("got connection on 9000");
        }
    });

    jh1.join().unwrap();

    Ok(())
}
