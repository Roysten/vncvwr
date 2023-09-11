use crate::d3des::{Des, Direction};
use crate::rfb::{self, RfbVersion};
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Debug)]
pub struct Session {
    stream: TcpStream,
    rfb_version: rfb::RfbVersion,
    pixel_format: Option<PixelFormat>,
    screen_w: u16,
    screen_h: u16,
    name: String,
}

#[derive(Debug)]
pub enum HandshakeError {
    IoError(std::io::Error),
    UnsupportedRfbVersion,
    UnsupportedSecurity(String),
    UnsupportedServerSettings(String),
}

#[derive(Debug)]
pub struct PixelFormat {
    bits_per_pixel: u8,
    depth: u8,
    big_endian_flag: u8,
    true_color_flag: u8,
    red_max: u16,
    green_max: u16,
    blue_max: u16,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,
}

impl From<[u8; 16]> for PixelFormat {
    fn from(src: [u8; 16]) -> Self {
        PixelFormat {
            bits_per_pixel: src[0],
            depth: src[1],
            big_endian_flag: src[2],
            true_color_flag: src[3],
            red_max: u16::from_be_bytes([src[4], src[5]]),
            green_max: u16::from_be_bytes([src[6], src[7]]),
            blue_max: u16::from_be_bytes([src[8], src[9]]),
            red_shift: src[10],
            green_shift: src[11],
            blue_shift: src[12],
        }
    }
}

impl From<&PixelFormat> for [u8; 16] {
    fn from(src: &PixelFormat) -> Self {
        [
            src.bits_per_pixel,
            src.depth,
            src.big_endian_flag,
            src.true_color_flag,
            (src.red_max >> 8) as u8,
            src.red_max as u8,
            (src.green_max >> 8) as u8,
            src.green_max as u8,
            (src.blue_max >> 8) as u8,
            src.blue_max as u8,
            src.red_shift,
            src.green_shift,
            src.blue_shift,
            0u8,
            0u8,
            0u8,
        ]
    }
}

impl From<std::io::Error> for HandshakeError {
    fn from(err: std::io::Error) -> Self {
        HandshakeError::IoError(err)
    }
}

impl Session {
    pub const PREFERRED_PIXEL_FORMAT: PixelFormat = PixelFormat {
        bits_per_pixel: 32,
        depth: 24,
        big_endian_flag: 0,
        true_color_flag: 1,
        red_max: 255,
        green_max: 255,
        blue_max: 255,
        red_shift: 16,
        green_shift: 8,
        blue_shift: 0,
    };

    pub fn new(address: &str, port: u16) -> Result<Self, std::io::Error> {
        let stream = TcpStream::connect((address, port))?;
        Ok(Self {
            stream: stream,
            rfb_version: rfb::RfbVersion::Unsupported,
            pixel_format: None,
            screen_w: 0,
            screen_h: 0,
            name: String::new(),
        })
    }

    pub fn handshake(&mut self) -> Result<(), HandshakeError> {
        self.rfb_version = Self::handle_protocol_version(&mut self.stream)?;
        let security = Self::handle_security_handshake(&mut self.stream)?;

        let shared = [0u8];
        self.stream.write_all(&shared);

        self.screen_w = Self::read_u16(&mut self.stream)?;
        self.screen_h = Self::read_u16(&mut self.stream)?;

        let mut pixel_format = [0u8; 16];
        self.stream.read_exact(&mut pixel_format)?;
        self.pixel_format = Some(pixel_format.into());

        let name_len = Self::read_u32(&mut self.stream)?;
        if name_len > 1000 {
            return Err(HandshakeError::UnsupportedServerSettings(
                "Too long name".to_string(),
            ));
        }
        let mut name = Self::read_dynamic(&mut self.stream, name_len as usize)?;
        self.name = String::from_utf8(name).unwrap();
        Ok(())
    }

    pub fn set_pixel_format(&mut self, format: &PixelFormat) -> Result<(), std::io::Error> {
        self.stream.write_all(&[0u8, 0, 0, 0])?;
        let encoded: [u8; 16] = format.into();
        self.stream.write_all(&encoded[..])
    }

    /**
     * Set encodings in order of preference. First element is most preferred.
     */
    pub fn set_encodings(&mut self, encodings: &[rfb::Encoding]) -> Result<(), std::io::Error> {
        let encoding_data: Vec<u8> = encodings
            .iter()
            .map(|&x| (x as i32).to_be_bytes())
            .flatten()
            .collect();
        let len_data = (encodings.len() as u16).to_be_bytes();
        self.stream.write_all(&[2u8, 0, len_data[0], len_data[1]])?;
        self.stream.write_all(&encoding_data)
    }

    pub fn framebuffer_update_request(
        &mut self,
        incremental: bool,
        xpos: u16,
        ypos: u16,
        width: u16,
        height: u16,
    ) -> Result<(), std::io::Error> {
        self.stream.write_all(&[
            3u8,
            incremental as u8,
            (xpos >> 8) as u8,
            xpos as u8,
            (ypos >> 8) as u8,
            ypos as u8,
            (width >> 8) as u8,
            width as u8,
            (height >> 8) as u8,
            height as u8,
        ])
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
