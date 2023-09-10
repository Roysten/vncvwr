#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityType {
    Invalid = 0,
    None = 1,
    VncAuth = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RfbVersion {
    Rfb33,
    Rfb37,
    Rfb38,
    Unsupported,
}

fn as_digit(ascii_char: u8) -> u8 {
    ascii_char - b'0'
}

pub fn parse_offered_version(data: &[u8]) -> RfbVersion {
    if data.len() != 12
        || &data[0..=3] != b"RFB "
        || data[4..=6].iter().any(|x| !x.is_ascii_digit())
        || data[7] != b'.'
        || data[8..=10].iter().any(|x| !x.is_ascii_digit())
    {
        return RfbVersion::Unsupported;
    }

    let major = as_digit(data[4]) * 100 + as_digit(data[5]) * 10 + as_digit(data[6]);
    let minor = as_digit(data[8]) * 100 + as_digit(data[9]) * 10 + as_digit(data[10]);
    match (major, minor) {
        (3, 3) => RfbVersion::Rfb33,
        (3, 7) => RfbVersion::Rfb37,
        (3, 8) => RfbVersion::Rfb38,
        _ => RfbVersion::Unsupported,
    }
}
