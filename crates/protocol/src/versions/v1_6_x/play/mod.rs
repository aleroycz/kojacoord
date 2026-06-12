use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::codec::{Decode, Encode, PacketId};
use crate::error::ProtocolError;

fn need(src: &Bytes, n: usize) -> Result<(), ProtocolError> {
    if src.remaining() < n {
        Err(ProtocolError::UnexpectedEof)
    } else {
        Ok(())
    }
}

/// Pre-netty (1.6.x) strings are UCS-2 with a u16 BE length prefix.
fn encode_legacy_string(s: &str, dst: &mut BytesMut) {
    let units: Vec<u16> = s.encode_utf16().collect();
    dst.put_u16(units.len() as u16);
    for u in units {
        dst.put_u16(u);
    }
}

fn decode_legacy_string(src: &mut Bytes) -> Result<String, ProtocolError> {
    need(src, 2)?;
    let len = src.get_u16() as usize;
    need(src, len * 2)?;
    let mut units = Vec::with_capacity(len);
    for _ in 0..len {
        units.push(src.get_u16());
    }
    String::from_utf16(&units).map_err(|_| {
        ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid UCS-2 in pre-netty string",
        ))
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundKeepAlive {
    pub keep_alive_id: i32,
}

impl PacketId for ClientboundKeepAlive {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundKeepAlive")
    }
}

impl Encode for ClientboundKeepAlive {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.extend_from_slice(&self.keep_alive_id.to_be_bytes());
        Ok(())
    }
}

impl Decode for ClientboundKeepAlive {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        need(src, 4)?;
        Ok(Self {
            keep_alive_id: src.get_i32(),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundChatMessage {
    pub message: String,
}

impl PacketId for ClientboundChatMessage {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundChatMessage")
    }
}

impl Encode for ClientboundChatMessage {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        encode_legacy_string(&self.message, dst);
        Ok(())
    }
}

impl Decode for ClientboundChatMessage {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            message: decode_legacy_string(src)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundPlayerPosition {
    pub x: f64,
    pub y: f64,
    pub stance: f64,
    pub z: f64,
    pub yaw: f32,
    pub pitch: f32,
    pub on_ground: bool,
}

impl PacketId for ClientboundPlayerPosition {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundPlayerPosition")
    }
}

// Per the 1.6.4 Notchian decompile (Spigot/MCP `Packet13PlayerLookMove`,
// constructor signature `(double X, double stance, double Y, double Z,
// float yaw, float pitch, boolean onGround)`), the CLIENTBOUND order on
// the wire is `X, Stance, Y, Z` — Y and Stance swap relative to the
// serverbound Packet10Flying which is `X, Y, Stance, Z`. Encoding
// `X, Y, Stance, Z` into a clientbound 0x0D leaves the 1.6.4 client
// at the wrong altitude (it would interpret Stance + 1.62 as the eye
// position with Y as feet, but the actual feet/eye math then drifts
// because the field labels are swapped) — fall-through symptom is the
// player floating or sinking into the ground on the limbo spawn.
impl Encode for ClientboundPlayerPosition {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_f64(self.x);
        dst.put_f64(self.stance);
        dst.put_f64(self.y);
        dst.put_f64(self.z);
        dst.put_f32(self.yaw);
        dst.put_f32(self.pitch);
        dst.put_u8(self.on_ground as u8);
        Ok(())
    }
}

impl Decode for ClientboundPlayerPosition {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        need(src, 8 + 8 + 8 + 8 + 4 + 4 + 1)?;
        Ok(Self {
            x: src.get_f64(),
            stance: src.get_f64(),
            y: src.get_f64(),
            z: src.get_f64(),
            yaw: src.get_f32(),
            pitch: src.get_f32(),
            on_ground: src.get_u8() != 0,
        })
    }
}

/// Pre-netty (1.6.x) **HeldItemChange** — `Packet16BlockItemSwitch` in
/// HexaCord / Notchian MCP + ProtocolSupport's
/// `clientbound game_v_1_5_2::PacketHeldItemChange`.
///
/// CRITICAL: the wire field is a **Short (i16, 2 bytes)**, not a Byte.
/// Notchian's `Packet16BlockItemSwitch::readPacketData` calls
/// `input.readShort()`. ProtocolSupport's encoder writes
/// `buf.writeShort(slot)`. The legacy item-id range went up to 65535
/// (potions / mob spawners use IDs > 127), so the wire shape was sized
/// for short even though server-side modern slot indices are 0-8.
///
/// A previous 1-byte encoding here desynced the entire downstream
/// packet stream by 1 byte — the 1.6.4 client would consume our next
/// packet's leading byte as the high half of `slotId`, then read every
/// subsequent packet at an offset of 1, eventually hitting a Short
/// field with a tiny `maxLen` (e.g. `Packet25Painting.title` with
/// `readString(in, 13)`) and disconnecting with
/// `"String length longer than maximum allowed (NNNNN > 13)"`.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundHeldItemChange {
    pub slot: i16,
}

impl PacketId for ClientboundHeldItemChange {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundHeldItemChange")
    }
}

impl Encode for ClientboundHeldItemChange {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_i16(self.slot);
        Ok(())
    }
}

impl Decode for ClientboundHeldItemChange {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        need(src, 2)?;
        Ok(Self {
            slot: src.get_i16(),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundPlayerAbilities {
    pub flags: u8,
    pub flying_speed: f32,
    pub walking_speed: f32,
}

impl PacketId for ClientboundPlayerAbilities {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundPlayerAbilities")
    }
}

impl Encode for ClientboundPlayerAbilities {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_u8(self.flags);
        dst.put_f32(self.flying_speed);
        dst.put_f32(self.walking_speed);
        Ok(())
    }
}

impl Decode for ClientboundPlayerAbilities {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        need(src, 1 + 4 + 4)?;
        Ok(Self {
            flags: src.get_u8(),
            flying_speed: src.get_f32(),
            walking_speed: src.get_f32(),
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
        encode_legacy_string(&self.reason, dst);
        Ok(())
    }
}

impl Decode for ClientboundDisconnect {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        Ok(Self {
            reason: decode_legacy_string(src)?,
        })
    }
}

/// Per the ProtocolSupport 1.6 `RespawnPacket` reference impl
/// (mirrors the Notchian 1.6.4 `Packet9Respawn` encoder), the wire
/// shape is:
///   * dimension     : i32  (the **client-side** dimension index;
///                            -1 Nether / 0 Overworld / 1 End)
///   * difficulty    : u8
///   * gamemode      : u8
///   * world_height  : i16  (Notchian hardcodes 256)
///   * level_type    : String (UCS-2 short-prefix, e.g. `"default"`,
///                              `"flat"`)
///
/// The previous shape (`dimension: i8`, no `level_type`) sent 5 bytes
/// where the client expected at least 4+1+1+2+(2+len*2) and would
/// either read garbage past the packet boundary or, with framed
/// transports, disconnect with "unexpected EOF" — the 1.6.4 client
/// rejects respawn frames that don't end on a valid level-type
/// string.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundRespawn {
    pub dimension: i32,
    pub difficulty: u8,
    pub gamemode: u8,
    pub world_height: i16,
    pub level_type: String,
}

impl PacketId for ClientboundRespawn {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundRespawn")
    }
}

impl Encode for ClientboundRespawn {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_i32(self.dimension);
        dst.put_u8(self.difficulty);
        dst.put_u8(self.gamemode);
        dst.put_i16(self.world_height);
        encode_legacy_string(&self.level_type, dst);
        Ok(())
    }
}

impl Decode for ClientboundRespawn {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        need(src, 4 + 1 + 1 + 2)?;
        let dimension = src.get_i32();
        let difficulty = src.get_u8();
        let gamemode = src.get_u8();
        let world_height = src.get_i16();
        let level_type = decode_legacy_string(src)?;
        Ok(Self {
            dimension,
            difficulty,
            gamemode,
            world_height,
            level_type,
        })
    }
}

/// Pre-netty (1.6.x) **SpawnPosition** — `Packet6SpawnPosition` in
/// HexaCord / KettleCord + ProtocolSupport
/// `clientbound game_v_1_5_2::PacketPlayerSpawnPosition`.
///
/// Tells the client where its compass should point. The 1.6.x client
/// renders a flat "no compass" UI without it. Sent once, right after
/// `LoginRequest`. Field order matches `Packet6SpawnPosition::write`:
///   `[i32 x] [i32 y] [i32 z]`
#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundSpawnPosition {
    pub x: i32,
    pub y: i32,
    pub z: i32,
}

impl PacketId for ClientboundSpawnPosition {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundSpawnPosition")
    }
}

impl Encode for ClientboundSpawnPosition {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_i32(self.x);
        dst.put_i32(self.y);
        dst.put_i32(self.z);
        Ok(())
    }
}

impl Decode for ClientboundSpawnPosition {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        need(src, 12)?;
        Ok(Self {
            x: src.get_i32(),
            y: src.get_i32(),
            z: src.get_i32(),
        })
    }
}

/// Pre-netty (1.6.x) **TimeUpdate** — `Packet4UpdateTime`. Without it
/// the limbo world stays frozen at midnight and the client renders a
/// black sky. ProtocolSupport's `PacketTime` emits this once per
/// tick at minimum; for limbo we send it once at spawn.
///
/// Wire shape (HexaCord `Packet4UpdateTime::write`):
///   `[i64 world_age] [i64 time_of_day]`
#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundTimeUpdate {
    pub world_age: i64,
    pub time_of_day: i64,
}

impl PacketId for ClientboundTimeUpdate {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundTimeUpdate")
    }
}

impl Encode for ClientboundTimeUpdate {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_i64(self.world_age);
        dst.put_i64(self.time_of_day);
        Ok(())
    }
}

impl Decode for ClientboundTimeUpdate {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        need(src, 16)?;
        Ok(Self {
            world_age: src.get_i64(),
            time_of_day: src.get_i64(),
        })
    }
}

/// Pre-netty (1.6.x) **UpdateHealth** — `Packet8UpdateHealth`. Without
/// this the client renders the respawn screen (empty hearts) and
/// refuses input, since it thinks the player is dead. Sending health
/// > 0 immediately after `LoginRequest` keeps the HUD interactive.
///
/// Wire shape (HexaCord `Packet8UpdateHealth::write`):
///   `[f32 health] [i16 food] [f32 food_saturation]`
#[derive(Debug, Clone, PartialEq)]
pub struct ClientboundUpdateHealth {
    pub health: f32,
    pub food: i16,
    pub food_saturation: f32,
}

impl PacketId for ClientboundUpdateHealth {
    fn packet_id(ver: u32) -> u8 {
        crate::registry::cb_play(ver, "ClientboundUpdateHealth")
    }
}

impl Encode for ClientboundUpdateHealth {
    fn encode(&self, dst: &mut BytesMut) -> Result<(), ProtocolError> {
        dst.put_f32(self.health);
        dst.put_i16(self.food);
        dst.put_f32(self.food_saturation);
        Ok(())
    }
}

impl Decode for ClientboundUpdateHealth {
    fn decode(src: &mut Bytes) -> Result<Self, ProtocolError> {
        need(src, 10)?;
        Ok(Self {
            health: src.get_f32(),
            food: src.get_i16(),
            food_saturation: src.get_f32(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SpawnPosition is exactly 12 bytes (3 × i32 BE) and round-trips.
    #[test]
    fn spawn_position_round_trip() {
        let original = ClientboundSpawnPosition {
            x: 1,
            y: 256,
            z: -3,
        };
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 12);
        // Y = 0x00000100 BE at offset 4..8
        assert_eq!(&buf[4..8], &[0x00, 0x00, 0x01, 0x00]);
        let decoded = ClientboundSpawnPosition::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, original);
    }

    /// TimeUpdate is exactly 16 bytes (2 × i64 BE) and round-trips.
    #[test]
    fn time_update_round_trip() {
        let original = ClientboundTimeUpdate {
            world_age: 1000,
            time_of_day: 6000,
        };
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 16);
        let decoded = ClientboundTimeUpdate::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, original);
    }

    /// UpdateHealth is exactly 10 bytes (f32 + i16 + f32) and round-trips.
    #[test]
    fn update_health_round_trip() {
        let original = ClientboundUpdateHealth {
            health: 20.0,
            food: 20,
            food_saturation: 5.0,
        };
        let mut buf = BytesMut::new();
        original.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 10);
        let decoded = ClientboundUpdateHealth::decode(&mut buf.freeze()).unwrap();
        assert_eq!(decoded, original);
    }
}
