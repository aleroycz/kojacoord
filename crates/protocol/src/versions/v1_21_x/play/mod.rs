use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::codec::{Decode, Encode, PacketId};
use crate::error::ProtocolError;
use crate::types::VarInt;

fn need(src: &Bytes, n: usize) -> Result<(), ProtocolError> {
    if src.remaining() < n {
        Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("need {} bytes, only {} remaining", n, src.remaining()),
        )))
    } else {
        Ok(())
    }
}

fn encode_string(s: &str, dst: &mut BytesMut) -> Result<(), ProtocolError> {
    VarInt(s.len() as i32).encode(dst)?;
    dst.extend_from_slice(s.as_bytes());
    Ok(())
}

fn decode_string(src: &mut Bytes) -> Result<String, ProtocolError> {
    let len = VarInt::decode(src)?.0 as usize;
    need(src, len)?;
    let bytes = src.copy_to_bytes(len);
    String::from_utf8(bytes.to_vec()).map_err(|_| {
        ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid utf-8 string",
        ))
    })
}

pub use packets::{
    ClientboundDisconnect, ClientboundKeepAlive, ClientboundLogin, ClientboundPlayerAbilities,
    ClientboundPlayerPosition, ClientboundRespawn, ClientboundSetCarriedItem, ClientboundSound,
    ClientboundSystemChat,
};

mod packets {
    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    pub struct ClientboundKeepAlive {
        pub keep_alive_id: i64,
    }

    impl PacketId for ClientboundKeepAlive {
        fn packet_id(ver: u32) -> u8 {
            crate::registry::cb_play(ver, "ClientboundKeepAlive")
        }
    }

    impl Encode for ClientboundKeepAlive {
        fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
            self.keep_alive_id.encode(dst)
        }
    }

    impl Decode for ClientboundKeepAlive {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            Ok(Self {
                keep_alive_id: i64::decode(src)?,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ClientboundPlayerPosition {
        pub x: f64,
        pub y: f64,
        pub z: f64,
        pub yaw: f32,
        pub pitch: f32,
        pub flags: u8,
        pub teleport_id: VarInt,
    }

    impl PacketId for ClientboundPlayerPosition {
        fn packet_id(ver: u32) -> u8 {
            crate::registry::cb_play(ver, "ClientboundPlayerPosition")
        }
    }

    impl Encode for ClientboundPlayerPosition {
        fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
            dst.put_f64(self.x);
            dst.put_f64(self.y);
            dst.put_f64(self.z);
            dst.put_f32(self.yaw);
            dst.put_f32(self.pitch);
            dst.put_u8(self.flags);
            self.teleport_id.encode(dst)
        }
    }

    impl Decode for ClientboundPlayerPosition {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            need(src, 8 + 8 + 8 + 4 + 4 + 1)?;
            Ok(Self {
                x: src.get_f64(),
                y: src.get_f64(),
                z: src.get_f64(),
                yaw: src.get_f32(),
                pitch: src.get_f32(),
                flags: src.get_u8(),
                teleport_id: VarInt::decode(src)?,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ClientboundSystemChat {
        pub json_message: String,
        pub overlay: bool,
    }

    impl PacketId for ClientboundSystemChat {
        fn packet_id(ver: u32) -> u8 {
            crate::registry::cb_play(ver, "ClientboundSystemChat")
        }
    }

    impl Encode for ClientboundSystemChat {
        fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
            encode_string(&self.json_message, dst)?;
            dst.put_u8(self.overlay as u8);
            Ok(())
        }
    }

    impl Decode for ClientboundSystemChat {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            let json_message = decode_string(src)?;
            need(src, 1)?;
            let overlay = src.get_u8() != 0;
            Ok(Self {
                json_message,
                overlay,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ClientboundLogin {
        pub entity_id: i32,
        pub is_hardcore: bool,
        pub dimension_names: Vec<String>,
        pub max_players: VarInt,
        pub view_distance: VarInt,
        pub simulation_distance: VarInt,
        pub reduced_debug_info: bool,
        pub enable_respawn_screen: bool,
        pub do_limited_crafting: bool,
        pub dimension_type: VarInt,
        pub dimension_name: String,
        pub hashed_seed: i64,
        pub game_mode: u8,
        pub previous_game_mode: i8,
        pub is_debug: bool,
        pub is_flat: bool,
        pub death_location: Option<(String, i64)>,
        pub portal_cooldown: VarInt,
        /// Per BungeeCord `protocol/Login.java::read`: `seaLevel` was
        /// added in proto 768 (1.21.2). For proto 767 (1.21 / 1.21.1)
        /// the field is absent on the wire. `None` ⇒ omit.
        pub sea_level: Option<VarInt>,
        /// Per BungeeCord `Login.java::read`: `secureProfile` has been
        /// mandatory since proto 766 (1.20.5). Every v1_21_x proto
        /// (767+) carries it.
        pub secure_profile: bool,
    }

    impl PacketId for ClientboundLogin {
        fn packet_id(ver: u32) -> u8 {
            crate::registry::cb_play(ver, "ClientboundLogin")
        }
    }

    impl Encode for ClientboundLogin {
        fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
            dst.put_i32(self.entity_id);
            dst.put_u8(self.is_hardcore as u8);
            self.dimension_names.encode(dst)?;
            self.max_players.encode(dst)?;
            self.view_distance.encode(dst)?;
            self.simulation_distance.encode(dst)?;
            dst.put_u8(self.reduced_debug_info as u8);
            dst.put_u8(self.enable_respawn_screen as u8);
            dst.put_u8(self.do_limited_crafting as u8);
            self.dimension_type.encode(dst)?;
            encode_string(&self.dimension_name, dst)?;
            dst.put_i64(self.hashed_seed);
            dst.put_u8(self.game_mode);
            dst.put_i8(self.previous_game_mode);
            dst.put_u8(self.is_debug as u8);
            dst.put_u8(self.is_flat as u8);
            match &self.death_location {
                Some((dim, pos)) => {
                    dst.put_u8(1);
                    encode_string(dim, dst)?;
                    dst.put_i64(*pos);
                },
                None => dst.put_u8(0),
            }
            self.portal_cooldown.encode(dst)?;
            if let Some(s) = &self.sea_level {
                s.encode(dst)?;
            }
            dst.put_u8(self.secure_profile as u8);
            Ok(())
        }
    }

    impl Decode for ClientboundLogin {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            need(src, 4)?;
            let entity_id = src.get_i32();
            need(src, 1)?;
            let is_hardcore = src.get_u8() != 0;
            let dimension_names = Vec::<String>::decode(src)?;
            let max_players = VarInt::decode(src)?;
            let view_distance = VarInt::decode(src)?;
            let simulation_distance = VarInt::decode(src)?;
            need(src, 3)?;
            let reduced_debug_info = src.get_u8() != 0;
            let enable_respawn_screen = src.get_u8() != 0;
            let do_limited_crafting = src.get_u8() != 0;
            let dimension_type = VarInt::decode(src)?;
            let dimension_name = decode_string(src)?;
            need(src, 8)?;
            let hashed_seed = src.get_i64();
            need(src, 4)?;
            let game_mode = src.get_u8();
            let previous_game_mode = src.get_i8();
            let is_debug = src.get_u8() != 0;
            let is_flat = src.get_u8() != 0;
            need(src, 1)?;
            let death_location = if src.get_u8() != 0 {
                let dim = decode_string(src)?;
                need(src, 8)?;
                let pos = src.get_i64();
                Some((dim, pos))
            } else {
                None
            };
            let portal_cooldown = VarInt::decode(src)?;
            // Decoder lacks proto context — round-trip defaults to the
            // 1.21.2+ shape (sea_level present). Pre-1.21.2 callers
            // reconstructing must set this to None explicitly.
            let sea_level = if src.remaining() >= 2 {
                Some(VarInt::decode(src)?)
            } else {
                None
            };
            need(src, 1)?;
            let secure_profile = src.get_u8() != 0;
            Ok(Self {
                entity_id,
                is_hardcore,
                dimension_names,
                max_players,
                view_distance,
                simulation_distance,
                reduced_debug_info,
                enable_respawn_screen,
                do_limited_crafting,
                dimension_type,
                dimension_name,
                hashed_seed,
                game_mode,
                previous_game_mode,
                is_debug,
                is_flat,
                death_location,
                portal_cooldown,
                sea_level,
                secure_profile,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ClientboundRespawn {
        pub dimension_type: VarInt,
        pub dimension_name: String,
        pub hashed_seed: i64,
        pub game_mode: u8,
        pub previous_game_mode: i8,
        pub is_debug: bool,
        pub is_flat: bool,
        pub data_kept: u8,
        pub death_location: Option<(String, i64)>,
        pub portal_cooldown: VarInt,
        pub sea_level: Option<VarInt>,
    }

    impl PacketId for ClientboundRespawn {
        fn packet_id(ver: u32) -> u8 {
            crate::registry::cb_play(ver, "ClientboundRespawn")
        }
    }

    impl Encode for ClientboundRespawn {
        fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
            self.dimension_type.encode(dst)?;
            encode_string(&self.dimension_name, dst)?;
            dst.put_i64(self.hashed_seed);
            dst.put_u8(self.game_mode);
            dst.put_i8(self.previous_game_mode);
            dst.put_u8(self.is_debug as u8);
            dst.put_u8(self.is_flat as u8);
            dst.put_u8(self.data_kept);
            match &self.death_location {
                Some((dim, pos)) => {
                    dst.put_u8(1);
                    encode_string(dim, dst)?;
                    dst.put_i64(*pos);
                },
                None => dst.put_u8(0),
            }
            self.portal_cooldown.encode(dst)?;
            if let Some(s) = &self.sea_level {
                s.encode(dst)?;
            }
            Ok(())
        }
    }

    impl Decode for ClientboundRespawn {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            let dimension_type = VarInt::decode(src)?;
            let dimension_name = decode_string(src)?;
            need(src, 8)?;
            let hashed_seed = src.get_i64();
            need(src, 4)?;
            let game_mode = src.get_u8();
            let previous_game_mode = src.get_i8();
            let is_debug = src.get_u8() != 0;
            let is_flat = src.get_u8() != 0;
            need(src, 1)?;
            let data_kept = src.get_u8();
            need(src, 1)?;
            let death_location = if src.get_u8() != 0 {
                let dim = decode_string(src)?;
                need(src, 8)?;
                let pos = src.get_i64();
                Some((dim, pos))
            } else {
                None
            };
            let portal_cooldown = VarInt::decode(src)?;
            let sea_level = if src.remaining() >= 1 {
                Some(VarInt::decode(src)?)
            } else {
                None
            };
            Ok(Self {
                dimension_type,
                dimension_name,
                hashed_seed,
                game_mode,
                previous_game_mode,
                is_debug,
                is_flat,
                data_kept,
                death_location,
                portal_cooldown,
                sea_level,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ClientboundSound {
        pub sound_type: VarInt,
        pub sound_name: String,
        pub sound_category: VarInt,
        pub effect_pos_x: i32,
        pub effect_pos_y: i32,
        pub effect_pos_z: i32,
        pub volume: f32,
        pub pitch: f32,
        pub seed: i64,
    }

    impl PacketId for ClientboundSound {
        fn packet_id(ver: u32) -> u8 {
            crate::registry::cb_play(ver, "ClientboundSound")
        }
    }

    impl Encode for ClientboundSound {
        fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
            self.sound_type.encode(dst)?;
            encode_string(&self.sound_name, dst)?;
            self.sound_category.encode(dst)?;
            dst.put_i32(self.effect_pos_x);
            dst.put_i32(self.effect_pos_y);
            dst.put_i32(self.effect_pos_z);
            dst.put_f32(self.volume);
            dst.put_f32(self.pitch);
            dst.put_i64(self.seed);
            Ok(())
        }
    }

    impl Decode for ClientboundSound {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            let sound_type = VarInt::decode(src)?;
            let sound_name = decode_string(src)?;
            let sound_category = VarInt::decode(src)?;
            need(src, 4 + 4 + 4 + 4 + 4 + 8)?;
            let effect_pos_x = src.get_i32();
            let effect_pos_y = src.get_i32();
            let effect_pos_z = src.get_i32();
            let volume = src.get_f32();
            let pitch = src.get_f32();
            let seed = src.get_i64();
            Ok(Self {
                sound_type,
                sound_name,
                sound_category,
                effect_pos_x,
                effect_pos_y,
                effect_pos_z,
                volume,
                pitch,
                seed,
            })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ClientboundDisconnect {
        pub reason: String,
    }

    impl PacketId for ClientboundDisconnect {
        fn packet_id(ver: u32) -> u8 {
            crate::registry::cb_play(ver, "ClientboundDisconnect")
        }
    }

    impl Encode for ClientboundDisconnect {
        fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
            encode_string(&self.reason, dst)
        }
    }

    impl Decode for ClientboundDisconnect {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            Ok(Self {
                reason: decode_string(src)?,
            })
        }
    }

    // ── Opaque body packets (proxy treats these as raw bytes). ──────────────
    //
    // The 1.21+ wire shape for PlayerAbilities and SetCarriedItem is
    // small but very fiddly (1.21 SetCarriedItem became a VarInt, 1.21.2
    // added inventory deltas, etc.). The proxy only ever constructs
    // them with limbo defaults — we keep them as raw byte containers so
    // every patch revision routes through the registry id and the body
    // bytes the caller hands us.

    #[derive(Debug, Clone, PartialEq)]
    pub struct ClientboundPlayerAbilities {
        pub raw: Vec<u8>,
    }

    impl PacketId for ClientboundPlayerAbilities {
        fn packet_id(ver: u32) -> u8 {
            crate::registry::cb_play(ver, "ClientboundPlayerAbilities")
        }
    }

    impl Encode for ClientboundPlayerAbilities {
        fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
            dst.extend_from_slice(&self.raw);
            Ok(())
        }
    }

    impl Decode for ClientboundPlayerAbilities {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            Ok(Self {
                raw: src.copy_to_bytes(src.remaining()).to_vec(),
            })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ClientboundSetCarriedItem {
        pub raw: Vec<u8>,
    }

    impl PacketId for ClientboundSetCarriedItem {
        fn packet_id(ver: u32) -> u8 {
            crate::registry::cb_play(ver, "ClientboundSetCarriedItem")
        }
    }

    impl Encode for ClientboundSetCarriedItem {
        fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
            dst.extend_from_slice(&self.raw);
            Ok(())
        }
    }

    impl Decode for ClientboundSetCarriedItem {
        fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
            Ok(Self {
                raw: src.copy_to_bytes(src.remaining()).to_vec(),
            })
        }
    }
}
