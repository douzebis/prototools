// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! A tonic codec over prost messages with two application hooks at the point
//! where a message is raw bytes (spec 0377) — the last place before the wire:
//!
//! - its **decoder** hands each message's raw bytes to a decode callback
//!   before decoding (`set_decode_callback`): the decoding side reads the tags;
//! - its **encoder** rewrites each message's bytes through an encode callback
//!   before emitting them (`set_encode_callback`): the encoding side hides a
//!   bit field in the tags.
//!
//! `build.rs` points the generated service at this codec (`codec_path`), so
//! it wraps the client and the server alike. For the echo handshake (spec
//! 0379) both sides install both callbacks — the server reads requests and
//! writes responses, the client the reverse. A side that installs neither
//! gets a plain prost pass-through. Each process has its own callbacks, so
//! the shared statics below do not cross between client and server.

use bytes::{Buf, BufMut};
use prost::Message;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::Status;
use tonic_prost::ProstCodec;

/// What the server does with a request's raw bytes, on decode, installed once
/// before serving. Unset until then, so the decoder is a plain pass-through.
static DECODE_CALLBACK: std::sync::OnceLock<fn(&[u8])> = std::sync::OnceLock::new();

/// How the client rewrites an encoded message: the prost bytes in, the wire
/// bytes out.
type EncodeCallback = fn(&[u8]) -> Vec<u8>;

/// How the client rewrites a request's raw bytes, on encode, installed once
/// before the first call (spec 0377 S7). Unset until then, so the encoder
/// emits prost bytes unchanged.
static ENCODE_CALLBACK: std::sync::OnceLock<EncodeCallback> = std::sync::OnceLock::new();

/// Declare the callback the codec hands each decoded message's raw bytes to.
/// Whichever side decodes installs it: the server to read a request's tags
/// (spec 0377 S2), the client to read a response's (spec 0379 S3).
pub fn set_decode_callback(callback: fn(&[u8])) {
    let _ = DECODE_CALLBACK.set(callback);
}

/// Declare the callback that rewrites each encoded message's raw bytes before
/// they go on the wire (spec 0377 S7). The client calls this once, at startup.
pub fn set_encode_callback(callback: EncodeCallback) {
    let _ = ENCODE_CALLBACK.set(callback);
}

/// A codec identical to `ProstCodec`, except its decoder passes the raw
/// message bytes to the request callback before decoding.
#[derive(Debug)]
pub struct TagReadingCodec<Encode, Decode> {
    inner: ProstCodec<Encode, Decode>,
}

impl<Encode, Decode> Default for TagReadingCodec<Encode, Decode>
where
    Encode: Message + Send + 'static,
    Decode: Message + Default + Send + 'static,
{
    fn default() -> Self {
        Self {
            inner: ProstCodec::default(),
        }
    }
}

impl<Encode, Decode> Codec for TagReadingCodec<Encode, Decode>
where
    Encode: Message + Send + 'static,
    Decode: Message + Default + Send + 'static,
{
    type Encode = Encode;
    type Decode = Decode;
    type Encoder = CallbackEncoder<Encode, Decode>;
    type Decoder = CallbackDecoder<Encode, Decode>;

    fn encoder(&mut self) -> Self::Encoder {
        CallbackEncoder {
            inner: self.inner.encoder(),
        }
    }

    fn decoder(&mut self) -> Self::Decoder {
        CallbackDecoder {
            inner: self.inner.decoder(),
        }
    }
}

/// Hands the raw buffer to the request callback, then delegates to the
/// prost decoder. The buffer holds exactly one message's bytes.
pub struct CallbackDecoder<Encode, Decode>
where
    Encode: Message + Send + 'static,
    Decode: Message + Default + Send + 'static,
{
    inner: <ProstCodec<Encode, Decode> as Codec>::Decoder,
}

impl<Encode, Decode> Decoder for CallbackDecoder<Encode, Decode>
where
    Encode: Message + Send + 'static,
    Decode: Message + Default + Send + 'static,
{
    type Item = Decode;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        // `src.chunk()` is the message's bytes; reading does not consume
        // them, so the prost decoder still sees the whole message.
        if let Some(callback) = DECODE_CALLBACK.get() {
            callback(src.chunk());
        }
        self.inner.decode(src)
    }
}

/// Prost-encodes the message, then rewrites the bytes through the encode
/// callback before emitting them (spec 0377 S7). With no callback installed
/// it emits the prost bytes unchanged.
pub struct CallbackEncoder<Encode, Decode>
where
    Encode: Message + Send + 'static,
    Decode: Message + Default + Send + 'static,
{
    inner: <ProstCodec<Encode, Decode> as Codec>::Encoder,
}

impl<Encode, Decode> Encoder for CallbackEncoder<Encode, Decode>
where
    Encode: Message + Send + 'static,
    Decode: Message + Default + Send + 'static,
{
    type Item = Encode;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        let Some(callback) = ENCODE_CALLBACK.get() else {
            return self.inner.encode(item, dst);
        };
        let mut bytes = Vec::with_capacity(item.encoded_len());
        item.encode(&mut bytes)
            .map_err(|e| Status::internal(format!("encoding the request: {e}")))?;
        dst.put_slice(&callback(&bytes));
        Ok(())
    }
}
