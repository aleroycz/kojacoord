//! Minecraft Java Edition protocol types and dispatch.
//!
//! This crate is the wire-level vocabulary for everything in the
//! workspace. Submodules:
//!   - `codec` — the `Encode`/`Decode`/`PacketId` traits and primitive
//!     impls (varint, string, slot, etc.)
//!   - `types` — shared structures (`Position`, `Nbt`, `Slot`, chunk
//!     formats, flattening tables loaded from `data/*.toml`)
//!   - `negotiation` — `ProtocolVersion` table and "nearest known"
//!     resolution
//!   - `registry` — `(protocol, state, direction, name) → packet_id`
//!     lookup table
//!   - `versions::v1_*_x` — typed packet structs per release family
//!
//! The proxy crate dispatches on `ProtocolVersion::canonical_typed_packet_version()`
//! to pick which `versions::*` family to use for a given client.

#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::doc_overindented_list_items)]

pub mod codec;
pub mod dimension_codec;
pub mod error;
pub mod negotiation;
pub mod registry;
pub mod types;
pub mod versions;

pub use codec::{read_packet, write_packet, Decode, DecodeVer, Encode, EncodeVer, PacketId};
pub use dimension_codec::{
    dimension_codec_nbt, dimension_codec_nbt_1_20_4, dimension_type_nbt, dimension_type_nbt_1_20_4,
};
pub use error::ProtocolError;
pub use negotiation::{
    CanonicalVersion, Epoch, MinecraftEdition, ProtocolVersion, VersionRegistry,
};
pub use registry::{build_default_registry, Direction, PacketMeta, PacketRegistry, ProtocolState};
pub use types::flattening::{BlockFlatteningTable, ItemFlatteningTable};
pub use types::position::{
    decode_legacy_position, decode_modern_position, encode_legacy_position, encode_modern_position,
};
pub use types::{Position, Slot, VarInt, VarLong};
