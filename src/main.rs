mod d3des;
mod rfb;
mod session;

fn main() -> Result<(), std::io::Error> {
    let mut session = session::Session::new("127.0.0.1", 5901)?;
    let handshake_result = session.handshake();
    println!("{:?} {:?}", handshake_result, session);
    Ok(())
}
