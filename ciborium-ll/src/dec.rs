// SPDX-License-Identifier: Apache-2.0

use super::*;

use ciborium_io::{slice::SliceReader, Read};

#[cfg(feature = "half")]
use half::f16;

/// An error that occurred while decoding
#[derive(Clone, Debug)]
pub enum Error<T> {
    /// An error occurred while reading bytes
    ///
    /// Contains the underlying error returned while reading.
    Io(T),

    /// An error occurred while parsing bytes
    ///
    /// Contains the offset into the stream where the syntax error occurred.
    Syntax(usize),
}

impl<T> From<T> for Error<T> {
    #[inline]
    fn from(value: T) -> Self {
        Self::Io(value)
    }
}

/// A decoder for deserializing CBOR items
///
/// This decoder manages the low-level decoding of CBOR items into `Header`
/// objects. It also contains utility functions for parsing segmented bytes
/// and text inputs.
pub struct Decoder<R> {
    reader: R,
    offset: usize,
    buffer: Option<(Header, usize)>,
    last_header_len: usize,
}

impl<R: Read> From<R> for Decoder<R> {
    #[inline]
    fn from(value: R) -> Self {
        Self {
            reader: value,
            offset: 0,
            buffer: None,
            last_header_len: 0,
        }
    }
}

impl<R: Read> Read for Decoder<R> {
    type Error = R::Error;

    #[inline]
    fn read_exact(&mut self, data: &mut [u8]) -> Result<(), Self::Error> {
        assert!(self.buffer.is_none());
        self.reader.read_exact(data)?;
        self.offset += data.len();
        Ok(())
    }
}

impl<R: Read> Decoder<R> {
    #[inline]
    fn pull_header(&mut self) -> Result<Header, Error<R::Error>> {
        if let Some((header, len)) = self.buffer.take() {
            self.offset += len;
            self.last_header_len = len;
            return Ok(header);
        }

        let offset = self.offset;
        let mut prefix = [0u8; 1];
        self.read_exact(&mut prefix[..])?;

        let major = prefix[0] >> 5;
        let additional = prefix[0] & 0x1f;
        let value = match additional {
            value @ 0..=23 => Some(value.into()),
            24 => {
                let mut bytes = [0u8; 1];
                self.read_exact(&mut bytes)?;
                Some(u8::from_be_bytes(bytes).into())
            }
            25 => {
                let mut bytes = [0u8; 2];
                self.read_exact(&mut bytes)?;
                Some(u16::from_be_bytes(bytes).into())
            }
            26 => {
                let mut bytes = [0u8; 4];
                self.read_exact(&mut bytes)?;
                Some(u32::from_be_bytes(bytes).into())
            }
            27 => {
                let mut bytes = [0u8; 8];
                self.read_exact(&mut bytes)?;
                Some(u64::from_be_bytes(bytes))
            }
            31 => None,
            _ => return Err(Error::Syntax(offset)),
        };

        let header = match (major, additional, value) {
            (0, _, Some(value)) => Header::Positive(value),
            (1, _, Some(value)) => Header::Negative(value),
            (2, _, value) => Header::Bytes(
                value
                    .map(usize::try_from)
                    .transpose()
                    .map_err(|_| Error::Syntax(offset))?,
            ),
            (3, _, value) => Header::Text(
                value
                    .map(usize::try_from)
                    .transpose()
                    .map_err(|_| Error::Syntax(offset))?,
            ),
            (4, _, value) => Header::Array(
                value
                    .map(usize::try_from)
                    .transpose()
                    .map_err(|_| Error::Syntax(offset))?,
            ),
            (5, _, value) => Header::Map(
                value
                    .map(usize::try_from)
                    .transpose()
                    .map_err(|_| Error::Syntax(offset))?,
            ),
            (6, _, Some(value)) => Header::Tag(value),

            (7, 31, None) => Header::Break,
            (7, 0..=24, Some(value)) => Header::Simple(value as u8),
            (7, 25, Some(value)) => {
                #[cfg(feature = "half")]
                let value = f16::from_bits(value as u16);

                #[cfg(not(feature = "half"))]
                let value = f16::from_bits(value as u16);

                Header::Float(value.into())
            }
            (7, 26, Some(value)) => Header::Float(f32::from_bits(value as u32).into()),
            (7, 27, Some(value)) => Header::Float(f64::from_bits(value)),
            _ => return Err(Error::Syntax(offset)),
        };

        self.last_header_len = self.offset - offset;
        Ok(header)
    }

    /// Pulls the next header from the input
    #[inline]
    pub fn pull(&mut self) -> Result<Header, Error<R::Error>> {
        self.pull_header()
    }

    /// Push a single header into the input buffer
    ///
    /// # Panics
    ///
    /// This function panics if called while there is already a header in the
    /// input buffer. You should take care to call this function only after
    /// pulling a header to ensure there is nothing in the input buffer.
    #[inline]
    pub fn push(&mut self, item: Header) {
        assert!(self.buffer.is_none());
        self.offset -= self.last_header_len;
        self.buffer = Some((item, self.last_header_len));
    }

    /// Gets the current byte offset into the stream
    ///
    /// The offset starts at zero when the decoder is created. Therefore, if
    /// bytes were already read from the reader before the decoder was created,
    /// you must account for this.
    #[inline]
    pub fn offset(&mut self) -> usize {
        self.offset
    }

    /// Process an incoming bytes item
    ///
    /// In CBOR, bytes can be segmented. The logic for this can be a bit tricky,
    /// so we encapsulate that logic using this function. This function **MUST**
    /// be called immediately after first pulling a `Header::Bytes(len)` from
    /// the wire and `len` must be provided to this function from that value.
    ///
    /// The `buf` parameter provides a buffer used when reading in the segmented
    /// bytes. A large buffer will result in fewer calls to read incoming bytes
    /// at the cost of memory usage. You should consider this trade off when
    /// deciding the size of your buffer.
    #[inline]
    pub fn bytes<'a>(&'a mut self, len: Option<usize>) -> Segments<'a, R, crate::seg::Bytes> {
        self.push(Header::Bytes(len));
        Segments::new(self, |header| match header {
            Header::Bytes(len) => Ok(len),
            _ => Err(()),
        })
    }

    /// Process an incoming text item
    ///
    /// In CBOR, text can be segmented. The logic for this can be a bit tricky,
    /// so we encapsulate that logic using this function. This function **MUST**
    /// be called immediately after first pulling a `Header::Text(len)` from
    /// the wire and `len` must be provided to this function from that value.
    ///
    /// The `buf` parameter provides a buffer used when reading in the segmented
    /// text. A large buffer will result in fewer calls to read incoming bytes
    /// at the cost of memory usage. You should consider this trade off when
    /// deciding the size of your buffer.
    #[inline]
    pub fn text<'a>(&'a mut self, len: Option<usize>) -> Segments<'a, R, crate::seg::Text> {
        self.push(Header::Text(len));
        Segments::new(self, |header| match header {
            Header::Text(len) => Ok(len),
            _ => Err(()),
        })
    }
}

impl<'slice> Decoder<SliceReader<'slice>> {
    /// Attempts to borrow the next `len` bytes directly from the underlying slice.
    #[inline]
    pub fn try_borrow_slice(&mut self, len: usize) -> Option<&'slice [u8]> {
        let slice = self.reader.take(len);
        if slice.is_some() {
            self.offset += len;
        }
        slice
    }
}
