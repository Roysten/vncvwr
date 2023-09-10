use crate::d3des::{Des, Direction};
use crate::rfb::{self, RfbVersion};
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Debug)]
pub struct Session {
    stream: TcpStream,
    rfb_version: rfb::RfbVersion,
}

#[derive(Debug)]
pub enum HandshakeError {
    IoError(std::io::Error),
    UnsupportedRfbVersion,
    UnsupportedSecurity(String),
}

impl From<std::io::Error> for HandshakeError {
    fn from(err: std::io::Error) -> Self {
        HandshakeError::IoError(err)
    }
}

impl Session {
    pub fn new(address: &str, port: u16) -> Result<Self, std::io::Error> {
        let stream = TcpStream::connect((address, port))?;
        Ok(Self {
            stream: stream,
            rfb_version: rfb::RfbVersion::Unsupported,
        })
    }

    fn read_u8(stream: &mut TcpStream) -> Result<u8, std::io::Error> {
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u16(stream: &mut TcpStream) -> Result<u16, std::io::Error> {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    fn read_u32(stream: &mut TcpStream) -> Result<u32, std::io::Error> {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    fn read_dynamic(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = Vec::with_capacity(len);
        buf.resize(len, 0);
        stream.read_exact(buf.as_mut_slice())?;
        Ok(buf)
    }

    pub fn handshake(&mut self) -> Result<(), HandshakeError> {
        self.rfb_version = Self::handle_protocol_version(&mut self.stream)?;
        let security = Self::handle_security_handshake(&mut self.stream)?;

        let shared = [0u8];
        self.stream.write_all(&shared);

        let w = Self::read_u16(&mut self.stream)?;
        let h = Self::read_u16(&mut self.stream)?;
        let mut pixel_format = [0u8; 16];
        self.stream.read_exact(&mut pixel_format);
        let name_len = Self::read_u32(&mut self.stream)?;
        if name_len > 1000 {
            return Err(HandshakeError::UnsupportedRfbVersion);
        }
        let mut name = Self::read_dynamic(&mut self.stream, name_len as usize)?;
        let name = String::from_utf8(name);
        println!(
            "w: {} h: {} name len: {} name: {:?}",
            w,
            h,
            name_len,
            name.unwrap()
        );
        Ok(())
    }

    fn handle_protocol_version(stream: &mut TcpStream) -> Result<rfb::RfbVersion, HandshakeError> {
        let mut protocol_version = [0u8; 12];
        stream.read_exact(&mut protocol_version)?;
        let rfb_version = rfb::parse_offered_version(&protocol_version);
        if rfb_version != RfbVersion::Rfb38 {
            return Err(HandshakeError::UnsupportedRfbVersion);
        }
        stream.write_all(b"RFB 003.008\n")?;
        Ok(rfb_version)
    }

    fn handle_security_handshake(
        stream: &mut TcpStream,
    ) -> Result<rfb::SecurityType, HandshakeError> {
        let security_type_count = Self::read_u8(stream)?;
        if security_type_count == 0 {
            let reason_str_len = Self::read_u32(stream)? as usize;
            let mut reason_str = Self::read_dynamic(stream, std::cmp::min(1000, reason_str_len))?;
            return Err(HandshakeError::UnsupportedSecurity(
                String::from_utf8(reason_str).unwrap_or(String::new()),
            ));
        }

        let mut server_security_types = [0u8; 255];
        let slice = &mut server_security_types[0..security_type_count as usize];
        stream.read_exact(slice)?;

        let preferred_security_type =
            slice
                .iter()
                .fold(rfb::SecurityType::Invalid, |acc, &x| match (acc, x) {
                    (rfb::SecurityType::None, _) => acc,
                    (_, s) if s == rfb::SecurityType::None as u8 => rfb::SecurityType::None,
                    (_, s) if s == rfb::SecurityType::VncAuth as u8 => rfb::SecurityType::VncAuth,
                    _ => acc,
                });

        match preferred_security_type {
            rfb::SecurityType::None => Self::handle_none_auth(stream),
            rfb::SecurityType::VncAuth => Self::handle_vnc_auth(stream),
            _ => Err(HandshakeError::UnsupportedSecurity(
                "No suitable security".to_string(),
            )),
        }
    }

    fn handle_none_auth(stream: &mut TcpStream) -> Result<rfb::SecurityType, HandshakeError> {
        stream.write_all(&[rfb::SecurityType::None as u8])?;
        let security_handshake_result = Self::read_u32(stream)?;
        match security_handshake_result {
            0 => Ok(rfb::SecurityType::None),
            _ => Err(HandshakeError::UnsupportedSecurity(format!(
                "Security type not accepted by server ({})",
                security_handshake_result
            ))),
        }
    }

    fn handle_vnc_auth(stream: &mut TcpStream) -> Result<rfb::SecurityType, HandshakeError> {
        stream.write_all(&[rfb::SecurityType::VncAuth as u8])?;
        let mut challenge = [0u8; 16];
        stream.read_exact(&mut challenge)?;

        println!("Password:");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim_end();

        let mut passwd_buf = [0u8; 8];
        for i in 0..std::cmp::min(trimmed.len(), passwd_buf.len()) {
            passwd_buf[i] = trimmed.as_bytes()[i];
        }

        let des = Des::new(&passwd_buf, Direction::Encrypt);
        let block_a = des.encrypt_block(&challenge[0..8]);
        let block_b = des.encrypt_block(&challenge[8..16]);
        stream.write_all(&block_a);
        stream.write_all(&block_b);

        let security_handshake_result = Self::read_u32(stream)?;
        match security_handshake_result {
            0 => Ok(rfb::SecurityType::VncAuth),
            _ => Err(HandshakeError::UnsupportedSecurity(format!(
                "Security type not accepted by server ({})",
                security_handshake_result
            ))),
        }
    }
}
