// SPDX-License-Identifier: Apache-2.0

use super::*;

use ciborium_io::Write;

#[cfg(feature = "half")]
use half::f16;

#[inline(always)]
fn push_value<W: Write>(writer: &mut W, major: u8, value: u64) -> Result<(), W::Error> {
    let prefix = major << 5;
    match value {
        0..=23 => writer.write_all(&[prefix | value as u8]),
        24..=0xff => writer.write_all(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            let value = (value as u16).to_be_bytes();
            writer.write_all(&[prefix | 25, value[0], value[1]])
        }
        0x1_0000..=0xffff_ffff => {
            let value = (value as u32).to_be_bytes();
            writer.write_all(&[prefix | 26, value[0], value[1], value[2], value[3]])
        }
        _ => {
            let value = value.to_be_bytes();
            writer.write_all(&[
                prefix | 27,
                value[0],
                value[1],
                value[2],
                value[3],
                value[4],
                value[5],
                value[6],
                value[7],
            ])
        }
    }
}

/// An encoder for serializing CBOR items
///
/// This structure wraps a writer and provides convenience functions for
/// writing `Header` objects to the wire.
pub struct Encoder<W>(W);

impl<W: Write> From<W> for Encoder<W> {
    #[inline]
    fn from(value: W) -> Self {
        Self(value)
    }
}

impl<W: Write> Write for Encoder<W> {
    type Error = W::Error;

    #[inline]
    fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.0.write_all(data)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        self.0.flush()
    }
}

impl<W: Write> Encoder<W> {
    /// Unwraps the `Write`, consuming the `Encoder`.
    #[inline]
    pub fn into_inner(self) -> W {
        self.0
    }

    /// Push a `Header` to the wire
    #[inline(always)]
    pub fn push(&mut self, header: Header) -> Result<(), W::Error> {
        match header {
            Header::Positive(value) => push_value(&mut self.0, 0, value),
            Header::Negative(value) => push_value(&mut self.0, 1, value),
            Header::Bytes(Some(value)) => push_value(&mut self.0, 2, value as u64),
            Header::Text(Some(value)) => push_value(&mut self.0, 3, value as u64),
            Header::Array(Some(value)) => push_value(&mut self.0, 4, value as u64),
            Header::Map(Some(value)) => push_value(&mut self.0, 5, value as u64),
            Header::Tag(value) => push_value(&mut self.0, 6, value),

            Header::Bytes(None) => self.0.write_all(&[0x5f]),
            Header::Text(None) => self.0.write_all(&[0x7f]),
            Header::Array(None) => self.0.write_all(&[0x9f]),
            Header::Map(None) => self.0.write_all(&[0xbf]),
            Header::Break => self.0.write_all(&[0xff]),
            Header::Simple(value @ 0..=23) => self.0.write_all(&[0xe0 | value]),
            Header::Simple(value) => self.0.write_all(&[0xf8, value]),
            Header::Float(value) => {
                #[cfg(feature = "half")]
                let half = f16::from_f64(value);

                #[cfg(not(feature = "half"))]
                let half = value as f16;

                if f64::from(half).to_bits() == value.to_bits() {
                    let half = half.to_be_bytes();
                    self.0.write_all(&[0xf9, half[0], half[1]])
                } else {
                    let single = value as f32;
                    if f64::from(single).to_bits() == value.to_bits() {
                        let single = single.to_be_bytes();
                        self.0
                            .write_all(&[0xfa, single[0], single[1], single[2], single[3]])
                    } else {
                        let value = value.to_be_bytes();
                        self.0.write_all(&[
                            0xfb, value[0], value[1], value[2], value[3], value[4], value[5],
                            value[6], value[7],
                        ])
                    }
                }
            }
        }
    }

    /// Serialize a byte slice as CBOR
    ///
    /// Optionally, segment the output into `segment` size segments. Note that
    /// if `segment == Some(0)` it will be silently upgraded to `Some(1)`. This
    /// minimum value is highly inefficient and should not be relied upon.
    #[inline]
    pub fn bytes(
        &mut self,
        value: &[u8],
        segment: impl Into<Option<usize>>,
    ) -> Result<(), W::Error> {
        let max = segment.into().unwrap_or(value.len());
        let max = core::cmp::max(max, 1);

        if max >= value.len() {
            self.push(Header::Bytes(Some(value.len())))?;
            self.write_all(value)?;
        } else {
            self.push(Header::Bytes(None))?;

            for chunk in value.chunks(max) {
                self.push(Header::Bytes(Some(chunk.len())))?;
                self.write_all(chunk)?;
            }

            self.push(Header::Break)?;
        }

        Ok(())
    }

    /// Serialize a string slice as CBOR
    ///
    /// Optionally, segment the output into `segment` size segments. Note that
    /// since care is taken to ensure that each segment is itself a valid UTF-8
    /// string, if `segment` contains a value of less than 4, it will be
    /// silently upgraded to 4. This minimum value is highly inefficient and
    /// should not be relied upon.
    #[inline]
    pub fn text(&mut self, value: &str, segment: impl Into<Option<usize>>) -> Result<(), W::Error> {
        let max = segment.into().unwrap_or(value.len());
        let max = core::cmp::max(max, 4);

        if max >= value.len() {
            self.push(Header::Text(Some(value.len())))?;
            self.write_all(value.as_bytes())?;
        } else {
            self.push(Header::Text(None))?;

            let mut bytes = value.as_bytes();
            while !bytes.is_empty() {
                let mut len = core::cmp::min(bytes.len(), max);
                while len > 0 && core::str::from_utf8(&bytes[..len]).is_err() {
                    len -= 1
                }

                let (prefix, suffix) = bytes.split_at(len);
                self.push(Header::Text(Some(prefix.len())))?;
                self.write_all(prefix)?;
                bytes = suffix;
            }

            self.push(Header::Break)?;
        }

        Ok(())
    }
}
