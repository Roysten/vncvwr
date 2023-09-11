mod d3des;
mod rfb;
mod session;

fn main() -> Result<(), std::io::Error> {
    let mut session = session::Session::new("127.0.0.1", 5901)?;
    let handshake_result = session.handshake();
    println!("Handshake result: {:?}", handshake_result);
    println!("{:#?}", session);
    println!("{:?}", session.set_pixel_format(&session::Session::PREFERRED_PIXEL_FORMAT));
    println!("{:?}", session.set_encodings(&[rfb::Encoding::Raw]));
    Ok(())
}
