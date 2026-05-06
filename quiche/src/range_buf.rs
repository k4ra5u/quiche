// Copyright (C) 2025, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::cmp;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;
/* PATCH */
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Buffer holding data at a specific offset.
///
/// The data is stored in a `Vec<u8>` in such a way that it can be shared
/// between multiple `RangeBuf` objects.
///
/// Each `RangeBuf` will have its own view of that buffer, where the `start`
/// value indicates the initial offset within the `Vec`, and `len` indicates the
/// number of bytes, starting from `start` that are included.
///
/// In addition, `pos` indicates the current offset within the `Vec`, starting
/// from the very beginning of the `Vec`.
///
/// Finally, `off` is the starting offset for the specific `RangeBuf` within the
/// stream the buffer belongs to.
#[derive(Clone, Debug, Default)]
pub struct RangeBuf<F = DefaultBufFactory>
where
    F: BufFactory,
{
    /// The internal buffer holding the data.
    ///
    /// To avoid needless allocations when a RangeBuf is split, this field
    /// should be reference-counted so it can be shared between multiple
    /// RangeBuf objects, and sliced using the `start` and `len` values.
    pub data: F::Buf,

    /// The initial offset within the internal buffer.
    pub start: usize,

    /// The current offset within the internal buffer.
    pub pos: usize,

    /// The number of bytes in the buffer, from the initial offset.
    pub len: usize,

    /// The offset of the buffer within a stream.
    pub off: u64,

    /// Whether this contains the final byte in the stream.
    pub fin: bool,

    pub _bf: PhantomData<F>,
}

/// A trait for providing internal storage buffers for `RangeBuf`.
/// The associated type `Buf` can be any type that dereferences to
/// a slice, but should be fast to clone, eg. by wrapping it with an
/// [`Arc`].
pub trait BufFactory: Clone + Default + Debug {
    /// The type of the generated buffer.
    type Buf: Clone + Debug + AsRef<[u8]>;

    /// Generate a new buffer from a given slice, the buffer must contain the
    /// same data as the original slice.
    fn buf_from_slice(buf: &[u8]) -> Self::Buf;
}

/// A trait that enables zero-copy sends to quiche. When buffers produced
/// by the `BufFactory` implement this trait, quiche and h3 can supply the
/// raw buffers to be sent, instead of slices that must be copied first.
pub trait BufSplit {
    /// Split the buffer at a given point, after the split the old buffer
    /// must only contain the first `at` bytes, while the newly produced
    /// buffer must containt the remaining bytes.
    fn split_at(&mut self, at: usize) -> Self;

    /// Try to prepend a prefix to the buffer, return true if succeeded.
    fn try_add_prefix(&mut self, _prefix: &[u8]) -> bool {
        false
    }
}

/// The default [`BufFactory`] allocates buffers on the heap on demand.
#[derive(Debug, Clone, Default)]
pub struct DefaultBufFactory;

/// The default [`BufFactory::Buf`] is a boxed slice wrapped in an [`Arc`].
#[derive(Debug, Clone, Default)]
pub struct DefaultBuf(Arc<Box<[u8]>>);

impl BufFactory for DefaultBufFactory {
    type Buf = DefaultBuf;

    fn buf_from_slice(buf: &[u8]) -> Self::Buf {
        DefaultBuf(Arc::new(buf.into()))
    }
}

impl AsRef<[u8]> for DefaultBuf {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl<F: BufFactory> RangeBuf<F>
where
    F::Buf: Clone,
{
    /// Creates a new `RangeBuf` from the given slice.
    pub fn from(buf: &[u8], off: u64, fin: bool) -> RangeBuf<F> {
        Self::from_raw(F::buf_from_slice(buf), off, fin)
    }

    pub fn from_raw(data: F::Buf, off: u64, fin: bool) -> RangeBuf<F> {
        RangeBuf {
            len: data.as_ref().len(),
            data,
            start: 0,
            pos: 0,
            off,
            fin,
            _bf: Default::default(),
        }
    }

    /// Returns whether `self` holds the final offset in the stream.
    pub fn fin(&self) -> bool {
        self.fin
    }

    /// Returns the starting offset of `self`.
    pub fn off(&self) -> u64 {
        (self.off - self.start as u64) + self.pos as u64
    }

    /// Returns the final offset of `self`.
    pub fn max_off(&self) -> u64 {
        self.off() + self.len() as u64
    }

    /// Returns the length of `self`.
    pub fn len(&self) -> usize {
        self.len - (self.pos - self.start)
    }

    /// Returns true if `self` has a length of zero bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Consumes the starting `count` bytes of `self`.
    pub fn consume(&mut self, count: usize) {
        self.pos += count;
    }

    /// Splits the buffer into two at the given index.
    pub fn split_off(&mut self, at: usize) -> RangeBuf<F>
    where
        F::Buf: Clone + AsRef<[u8]>,
    {
        assert!(
            at <= self.len,
            "`at` split index (is {}) should be <= len (is {})",
            at,
            self.len
        );

        let buf = RangeBuf {
            data: self.data.clone(),
            start: self.start + at,
            pos: cmp::max(self.pos, self.start + at),
            len: self.len - at,
            off: self.off + at as u64,
            _bf: Default::default(),
            fin: self.fin,
        };

        self.pos = cmp::min(self.pos, self.start + at);
        self.len = at;
        self.fin = false;

        buf
    }
}

impl<F: BufFactory> Deref for RangeBuf<F> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data.as_ref()[self.pos..self.start + self.len]
    }
}

impl<F: BufFactory> Ord for RangeBuf<F> {
    fn cmp(&self, other: &RangeBuf<F>) -> cmp::Ordering {
        // Invert ordering to implement min-heap.
        self.off.cmp(&other.off).reverse()
    }
}

impl<F: BufFactory> PartialOrd for RangeBuf<F> {
    fn partial_cmp(&self, other: &RangeBuf<F>) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: BufFactory> Eq for RangeBuf<F> {}

impl<F: BufFactory> PartialEq for RangeBuf<F> {
    fn eq(&self, other: &RangeBuf<F>) -> bool {
        self.off == other.off
    }
}

/* PATCH */
// add Serialize and Deserialize for RangeBuf
impl Serialize for RangeBuf {
    fn serialize<S: Serializer>(
        &self, serializer: S,
    ) -> std::result::Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    {
        let mut state = serializer.serialize_struct("RangeBuf", 6)?;
        let mut data = self.data.as_ref().to_vec();
        state.serialize_field("data", &data)?;
        state.serialize_field("start", &self.start)?;
        state.serialize_field("pos", &self.pos)?;
        state.serialize_field("len", &self.len)?;
        state.serialize_field("off", &self.off)?;
        state.serialize_field("fin", &self.fin)?;
        state.serialize_field("_bf", &self._bf)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RangeBuf {
    fn deserialize<D>(
        deserializer: D,
    ) -> std::result::Result<RangeBuf, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Data,
            Start,
            Pos,
            Len,
            Off,
            Fin,
            BF,
        }

        struct RangeBufVisitor;

        impl<'de> Visitor<'de> for RangeBufVisitor {
            type Value = RangeBuf;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct RangeBuf")
            }

            fn visit_seq<V>(
                self, mut seq: V,
            ) -> std::result::Result<RangeBuf, <V as SeqAccess<'de>>::Error>
            where
                V: SeqAccess<'de>,
            {
                let data: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let start = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let pos = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let len = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let off = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(4, &self))?;
                let fin = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(5, &self))?;
                Ok(RangeBuf {
                    data: DefaultBufFactory::buf_from_slice(&data),
                    start,
                    pos,
                    len,
                    off,
                    fin,
                    _bf: Default::default(),
                })
            }

            fn visit_map<V>(
                self, mut map: V,
            ) -> std::result::Result<RangeBuf, <V as MapAccess<'de>>::Error>
            where
                V: MapAccess<'de>,
            {
                let mut data: Option<Vec<u8>> = None;
                let mut start = None;
                let mut pos = None;
                let mut len = None;
                let mut off = None;
                let mut fin = None;
                let mut _bf = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Data => {
                            if data.is_some() {
                                return Err(de::Error::duplicate_field("data"));
                            }
                            data = Some(map.next_value()?);
                        },
                        Field::Start => {
                            if start.is_some() {
                                return Err(de::Error::duplicate_field("start"));
                            }
                            start = Some(map.next_value()?);
                        },
                        Field::Pos => {
                            if pos.is_some() {
                                return Err(de::Error::duplicate_field("pos"));
                            }
                            pos = Some(map.next_value()?);
                        },
                        Field::Len => {
                            if len.is_some() {
                                return Err(de::Error::duplicate_field("len"));
                            }
                            len = Some(map.next_value()?);
                        },
                        Field::Off => {
                            if off.is_some() {
                                return Err(de::Error::duplicate_field("off"));
                            }
                            off = Some(map.next_value()?);
                        },
                        Field::Fin => {
                            if fin.is_some() {
                                return Err(de::Error::duplicate_field("fin"));
                            }
                            fin = Some(map.next_value()?);
                        },
                        Field::BF => {
                            if _bf.is_some() {
                                return Err(de::Error::duplicate_field("_bf"));
                            }
                            _bf = Some(map.next_value()?);
                        },
                    }
                }
                let data =
                    data.ok_or_else(|| de::Error::missing_field("data"))?;
                let start =
                    start.ok_or_else(|| de::Error::missing_field("start"))?;
                let pos = pos.ok_or_else(|| de::Error::missing_field("pos"))?;
                let len = len.ok_or_else(|| de::Error::missing_field("len"))?;
                let off = off.ok_or_else(|| de::Error::missing_field("off"))?;
                let fin = fin.ok_or_else(|| de::Error::missing_field("fin"))?;
                let _bf = _bf.ok_or_else(|| de::Error::missing_field("_bf"))?;
                Ok(RangeBuf {
                    data: DefaultBufFactory::buf_from_slice(&data),
                    start,
                    pos,
                    len,
                    off,
                    fin,
                    _bf: Default::default(),
                })
            }
        }

        const FIELDS: &'static [&'static str] =
            &["data", "start", "pos", "len", "off", "fin", "_bf"];
        deserializer.deserialize_struct("RangeBuf", FIELDS, RangeBufVisitor)
    }
}
