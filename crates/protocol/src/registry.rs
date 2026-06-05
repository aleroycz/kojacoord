use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolState {
    Handshake,
    Status,
    Login,
    Configuration,
    Play,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Serverbound,
    Clientbound,
}

#[derive(Debug, Clone)]
pub struct PacketMeta {
    pub id: u8,
    pub name: &'static str,
}

pub struct PacketRegistry {
    map: HashMap<ProtocolState, HashMap<Direction, Vec<(u32, PacketMeta)>>>,
}

impl PacketRegistry {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn register(
        &mut self,
        proto: u32,
        state: ProtocolState,
        dir: Direction,
        name: &'static str,
        id: u8,
    ) {
        let state_map = self.map.entry(state).or_default();
        let dir_vec = state_map.entry(dir).or_default();
        if let Some((_, meta)) = dir_vec
            .iter_mut()
            .find(|(p, meta)| *p == proto && meta.name == name)
        {
            meta.id = id;
        } else {
            dir_vec.push((proto, PacketMeta { id, name }));
        }
    }

    pub fn get_id(
        &self,
        proto: u32,
        state: ProtocolState,
        dir: Direction,
        name: &'static str,
    ) -> Option<u8> {
        let state_map = self.map.get(&state)?;
        let dir_vec = state_map.get(&dir)?;
        dir_vec
            .iter()
            .find(|(p, meta)| *p == proto && meta.name == name)
            .map(|(_, meta)| meta.id)
    }

    pub fn get_id_for_version(
        &self,
        proto: u32,
        state: ProtocolState,
        dir: Direction,
        name: &'static str,
    ) -> Option<u8> {
        let state_map = self.map.get(&state)?;
        let dir_vec = state_map.get(&dir)?;

        if let Some((_, meta)) = dir_vec
            .iter()
            .find(|(p, meta)| *p == proto && meta.name == name)
        {
            return Some(meta.id);
        }

        let mut best_proto: Option<u32> = None;
        let mut best_id: Option<u8> = None;
        for (p, meta) in dir_vec {
            if meta.name == name && *p <= proto && best_proto.is_none_or(|bp| *p > bp) {
                best_proto = Some(*p);
                best_id = Some(meta.id);
            }
        }
        best_id
    }

    pub fn get_name_from_id(
        &self,
        proto: u32,
        state: ProtocolState,
        dir: Direction,
        id: u8,
    ) -> Option<&'static str> {
        let state_map = self.map.get(&state)?;
        let dir_vec = state_map.get(&dir)?;

        if let Some((_, meta)) = dir_vec
            .iter()
            .find(|(p, meta)| *p == proto && meta.id == id)
        {
            return Some(meta.name);
        }

        let mut best_proto: Option<u32> = None;
        let mut best_name: Option<&'static str> = None;
        for (p, meta) in dir_vec {
            if meta.id == id && *p <= proto && best_proto.is_none_or(|bp| *p > bp) {
                best_proto = Some(*p);
                best_name = Some(meta.name);
            }
        }
        best_name
    }
}

impl Default for PacketRegistry {
    fn default() -> Self {
        build_default_registry()
    }
}

pub fn build_default_registry() -> PacketRegistry {
    let mut r = PacketRegistry::new();

    macro_rules! reg {
        ($proto:expr, $state:ident, $dir:ident, $name:expr, $id:expr) => {
            r.register($proto, ProtocolState::$state, Direction::$dir, $name, $id);
        };
    }

    reg!(78, Login, Serverbound, "HandshakeC2S", 0x02);
    reg!(78, Login, Clientbound, "EncryptionKeyRequestS2C", 0xFD);
    reg!(78, Login, Serverbound, "EncryptionKeyResponseC2S", 0xFC);
    reg!(78, Login, Clientbound, "LoginRequestS2C", 0x01);

    reg!(5, Handshake, Serverbound, "ServerboundHandshake", 0x00);
    reg!(5, Status, Serverbound, "ServerboundStatusRequest", 0x00);
    reg!(5, Status, Serverbound, "ServerboundPingRequest", 0x01);
    reg!(5, Status, Clientbound, "ClientboundStatusResponse", 0x00);
    reg!(5, Status, Clientbound, "ClientboundPongResponse", 0x01);
    reg!(5, Login, Serverbound, "ServerboundLoginStart", 0x00);
    reg!(5, Login, Serverbound, "ServerboundEncryptionResponse", 0x01);
    reg!(5, Login, Clientbound, "ClientboundLoginDisconnect", 0x00);
    reg!(5, Login, Clientbound, "ClientboundEncryptionRequest", 0x01);
    reg!(5, Login, Clientbound, "ClientboundLoginSuccess", 0x02);
    reg!(5, Login, Clientbound, "ClientboundSetCompression", 0x03);

    reg!(47, Handshake, Serverbound, "ServerboundHandshake", 0x00);
    reg!(47, Status, Serverbound, "ServerboundStatusRequest", 0x00);
    reg!(47, Status, Serverbound, "ServerboundPingRequest", 0x01);
    reg!(47, Status, Clientbound, "ClientboundStatusResponse", 0x00);
    reg!(47, Status, Clientbound, "ClientboundPongResponse", 0x01);
    reg!(47, Login, Serverbound, "ServerboundLoginStart", 0x00);
    reg!(
        47,
        Login,
        Serverbound,
        "ServerboundEncryptionResponse",
        0x01
    );
    reg!(47, Login, Clientbound, "ClientboundLoginDisconnect", 0x00);
    reg!(47, Login, Clientbound, "ClientboundEncryptionRequest", 0x01);
    reg!(47, Login, Clientbound, "ClientboundLoginSuccess", 0x02);
    reg!(47, Login, Clientbound, "ClientboundSetCompression", 0x03);

    // Version 335 (Minecraft 1.12.2)
    reg!(
        335,
        Play,
        Clientbound,
        "ClientboundLevelChunkWithLight",
        0x20
    );
    reg!(335, Play, Clientbound, "SPacketChunkData", 0x20);
    reg!(335, Play, Clientbound, "ClientboundJoinGame", 0x23);
    reg!(335, Play, Clientbound, "ClientboundRespawn", 0x35);
    reg!(335, Play, Clientbound, "ClientboundKeepAlive", 0x00);
    reg!(335, Play, Clientbound, "ClientboundChatMessage", 0x0F);
    reg!(335, Play, Clientbound, "ClientboundPluginMessage", 0x18);
    reg!(335, Play, Clientbound, "ClientboundDisconnect", 0x40);
    reg!(335, Play, Serverbound, "ServerboundKeepAlive", 0x0B);
    reg!(335, Play, Serverbound, "ServerboundChatMessage", 0x02);
    reg!(335, Play, Serverbound, "ServerboundPluginMessage", 0x09);

    reg!(340, Handshake, Serverbound, "ServerboundHandshake", 0x00);
    reg!(340, Status, Serverbound, "ServerboundStatusRequest", 0x00);
    reg!(340, Status, Serverbound, "ServerboundPingRequest", 0x01);
    reg!(340, Status, Clientbound, "ClientboundStatusResponse", 0x00);
    reg!(340, Status, Clientbound, "ClientboundPongResponse", 0x01);
    reg!(340, Login, Serverbound, "ServerboundLoginStart", 0x00);
    reg!(
        340,
        Login,
        Serverbound,
        "ServerboundEncryptionResponse",
        0x01
    );
    reg!(340, Login, Clientbound, "ClientboundLoginDisconnect", 0x00);
    reg!(
        340,
        Login,
        Clientbound,
        "ClientboundEncryptionRequest",
        0x01
    );
    reg!(340, Login, Clientbound, "ClientboundLoginSuccess", 0x02);
    reg!(340, Login, Clientbound, "ClientboundSetCompression", 0x03);

    reg!(754, Handshake, Serverbound, "ServerboundHandshake", 0x00);
    reg!(754, Status, Serverbound, "ServerboundStatusRequest", 0x00);
    reg!(754, Status, Serverbound, "ServerboundPingRequest", 0x01);
    reg!(754, Status, Clientbound, "ClientboundStatusResponse", 0x00);
    reg!(754, Status, Clientbound, "ClientboundPongResponse", 0x01);
    reg!(754, Login, Serverbound, "ServerboundLoginStart", 0x00);
    reg!(
        754,
        Login,
        Serverbound,
        "ServerboundEncryptionResponse",
        0x01
    );
    reg!(754, Login, Clientbound, "ClientboundLoginDisconnect", 0x00);
    reg!(
        754,
        Login,
        Clientbound,
        "ClientboundEncryptionRequest",
        0x01
    );
    reg!(754, Login, Clientbound, "ClientboundLoginSuccess", 0x02);
    reg!(754, Login, Clientbound, "ClientboundSetCompression", 0x03);

    reg!(762, Handshake, Serverbound, "ServerboundHandshake", 0x00);
    reg!(762, Status, Serverbound, "ServerboundStatusRequest", 0x00);
    reg!(762, Status, Serverbound, "ServerboundPingRequest", 0x01);
    reg!(762, Status, Clientbound, "ClientboundStatusResponse", 0x00);
    reg!(762, Status, Clientbound, "ClientboundPongResponse", 0x01);
    reg!(762, Login, Serverbound, "ServerboundLoginStart", 0x00);
    reg!(
        762,
        Login,
        Serverbound,
        "ServerboundEncryptionResponse",
        0x01
    );
    reg!(762, Login, Clientbound, "ClientboundLoginDisconnect", 0x00);
    reg!(
        762,
        Login,
        Clientbound,
        "ClientboundEncryptionRequest",
        0x01
    );
    reg!(762, Login, Clientbound, "ClientboundLoginSuccess", 0x02);
    reg!(762, Login, Clientbound, "ClientboundSetCompression", 0x03);
    reg!(
        762,
        Login,
        Serverbound,
        "ServerboundLoginPluginResponse",
        0x02
    );
    reg!(
        762,
        Login,
        Clientbound,
        "ClientboundLoginPluginRequest",
        0x04
    );

    reg!(765, Handshake, Serverbound, "ServerboundHandshake", 0x00);
    reg!(765, Status, Serverbound, "ServerboundStatusRequest", 0x00);
    reg!(765, Status, Serverbound, "ServerboundPingRequest", 0x01);
    reg!(765, Status, Clientbound, "ClientboundStatusResponse", 0x00);
    reg!(765, Status, Clientbound, "ClientboundPongResponse", 0x01);
    reg!(765, Login, Serverbound, "ServerboundLoginStart", 0x00);
    reg!(
        765,
        Login,
        Serverbound,
        "ServerboundEncryptionResponse",
        0x01
    );
    reg!(765, Login, Clientbound, "ClientboundLoginDisconnect", 0x00);
    reg!(
        765,
        Login,
        Clientbound,
        "ClientboundEncryptionRequest",
        0x01
    );
    reg!(765, Login, Clientbound, "ClientboundLoginSuccess", 0x02);
    reg!(765, Login, Clientbound, "ClientboundSetCompression", 0x03);
    reg!(
        765,
        Login,
        Serverbound,
        "ServerboundLoginPluginResponse",
        0x02
    );
    reg!(
        765,
        Login,
        Clientbound,
        "ClientboundLoginPluginRequest",
        0x04
    );
    reg!(
        765,
        Login,
        Serverbound,
        "ServerboundLoginAcknowledged",
        0x03
    );
    reg!(765, Configuration, Clientbound, "FinishConfiguration", 0x03);
    reg!(
        765,
        Configuration,
        Serverbound,
        "AcknowledgeFinishConfiguration",
        0x03
    );

    reg!(767, Handshake, Serverbound, "ServerboundHandshake", 0x00);
    reg!(767, Status, Serverbound, "ServerboundStatusRequest", 0x00);
    reg!(767, Status, Serverbound, "ServerboundPingRequest", 0x01);
    reg!(767, Status, Clientbound, "ClientboundStatusResponse", 0x00);
    reg!(767, Status, Clientbound, "ClientboundPongResponse", 0x01);
    reg!(767, Login, Serverbound, "ServerboundLoginStart", 0x00);
    reg!(
        767,
        Login,
        Serverbound,
        "ServerboundEncryptionResponse",
        0x01
    );
    reg!(767, Login, Clientbound, "ClientboundLoginDisconnect", 0x00);
    reg!(
        767,
        Login,
        Clientbound,
        "ClientboundEncryptionRequest",
        0x01
    );
    reg!(767, Login, Clientbound, "ClientboundLoginSuccess", 0x02);
    reg!(767, Login, Clientbound, "ClientboundSetCompression", 0x03);
    reg!(
        767,
        Login,
        Serverbound,
        "ServerboundLoginPluginResponse",
        0x02
    );
    reg!(
        767,
        Login,
        Clientbound,
        "ClientboundLoginPluginRequest",
        0x04
    );
    reg!(
        767,
        Login,
        Serverbound,
        "ServerboundLoginAcknowledged",
        0x03
    );
    reg!(767, Configuration, Clientbound, "FinishConfiguration", 0x03);
    reg!(
        767,
        Configuration,
        Serverbound,
        "AcknowledgeFinishConfiguration",
        0x03
    );

    reg!(754, Play, Clientbound, "ClientboundKeepAlive", 0x1F);
    reg!(754, Play, Clientbound, "ClientboundJoinGame", 0x24);
    reg!(754, Play, Clientbound, "ClientboundLogin", 0x24);
    reg!(754, Play, Clientbound, "ClientboundChatMessage", 0x0E);
    reg!(754, Play, Clientbound, "ClientboundSystemChat", 0x0E);
    reg!(754, Play, Clientbound, "ClientboundPlayerPosition", 0x34);
    reg!(754, Play, Clientbound, "ClientboundPluginMessage", 0x17);
    reg!(754, Play, Clientbound, "ClientboundRespawn", 0x39);
    reg!(754, Play, Clientbound, "ClientboundDisconnect", 0x19);
    reg!(754, Play, Serverbound, "ServerboundKeepAlive", 0x10);
    reg!(754, Play, Serverbound, "ServerboundChatMessage", 0x03);
    reg!(754, Play, Serverbound, "ServerboundInteract", 0x0E);
    reg!(754, Play, Serverbound, "ServerboundMovePlayerPos", 0x12);
    reg!(754, Play, Serverbound, "ServerboundMovePlayerRot", 0x13);
    reg!(754, Play, Serverbound, "ServerboundMovePlayerPosRot", 0x14);
    reg!(754, Play, Serverbound, "ServerboundPluginMessage", 0x0B);

    reg!(762, Play, Clientbound, "ClientboundBundle", 0x00);
    reg!(765, Play, Clientbound, "ClientboundBundle", 0x00);
    reg!(767, Play, Clientbound, "ClientboundBundle", 0x00);
    reg!(5, Play, Clientbound, "ClientboundSpawnEntity", 0x0E);
    reg!(47, Play, Clientbound, "ClientboundSpawnEntity", 0x0E);
    reg!(762, Play, Clientbound, "ClientboundSpawnEntity", 0x01);
    reg!(765, Play, Clientbound, "ClientboundSpawnEntity", 0x01);
    reg!(767, Play, Clientbound, "ClientboundSpawnEntity", 0x01);
    reg!(5, Play, Clientbound, "ClientboundSpawnExperienceOrb", 0x11);
    reg!(47, Play, Clientbound, "ClientboundSpawnExperienceOrb", 0x11);
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundSpawnExperienceOrb",
        0x02
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundSpawnExperienceOrb",
        0x02
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundSpawnExperienceOrb",
        0x02
    );
    reg!(5, Play, Clientbound, "ClientboundSpawnPlayer", 0x0C);
    reg!(47, Play, Clientbound, "ClientboundSpawnPlayer", 0x0C);
    reg!(762, Play, Clientbound, "ClientboundSpawnPlayer", 0x03);
    reg!(765, Play, Clientbound, "ClientboundSpawnPlayer", 0x03);
    reg!(767, Play, Clientbound, "ClientboundSpawnPlayer", 0x03);
    reg!(5, Play, Clientbound, "ClientboundEntityAnimation", 0x0B);
    reg!(47, Play, Clientbound, "ClientboundEntityAnimation", 0x0B);
    reg!(340, Play, Clientbound, "ClientboundEntityAnimation", 0x06);
    reg!(762, Play, Clientbound, "ClientboundEntityAnimation", 0x04);
    reg!(765, Play, Clientbound, "ClientboundEntityAnimation", 0x04);
    reg!(767, Play, Clientbound, "ClientboundEntityAnimation", 0x04);
    reg!(5, Play, Clientbound, "ClientboundAwardStats", 0x37);
    reg!(47, Play, Clientbound, "ClientboundAwardStats", 0x37);
    reg!(340, Play, Clientbound, "ClientboundAwardStats", 0x07);
    reg!(762, Play, Clientbound, "ClientboundAwardStats", 0x05);
    reg!(765, Play, Clientbound, "ClientboundAwardStats", 0x05);
    reg!(767, Play, Clientbound, "ClientboundAwardStats", 0x05);
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundAcknowledgeBlockChange",
        0x06
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundAcknowledgeBlockChange",
        0x06
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundAcknowledgeBlockChange",
        0x06
    );
    reg!(5, Play, Clientbound, "ClientboundBlockDestroyStage", 0x25);
    reg!(47, Play, Clientbound, "ClientboundBlockDestroyStage", 0x25);
    reg!(340, Play, Clientbound, "ClientboundBlockDestroyStage", 0x08);
    reg!(762, Play, Clientbound, "ClientboundBlockDestroyStage", 0x07);
    reg!(765, Play, Clientbound, "ClientboundBlockDestroyStage", 0x07);
    reg!(767, Play, Clientbound, "ClientboundBlockDestroyStage", 0x07);
    reg!(5, Play, Clientbound, "ClientboundBlockEntityData", 0x35);
    reg!(47, Play, Clientbound, "ClientboundBlockEntityData", 0x35);
    reg!(340, Play, Clientbound, "ClientboundBlockEntityData", 0x09);
    reg!(762, Play, Clientbound, "ClientboundBlockEntityData", 0x08);
    reg!(765, Play, Clientbound, "ClientboundBlockEntityData", 0x08);
    reg!(767, Play, Clientbound, "ClientboundBlockEntityData", 0x08);
    reg!(5, Play, Clientbound, "ClientboundBlockAction", 0x24);
    reg!(47, Play, Clientbound, "ClientboundBlockAction", 0x24);
    reg!(340, Play, Clientbound, "ClientboundBlockAction", 0x0A);
    reg!(762, Play, Clientbound, "ClientboundBlockAction", 0x09);
    reg!(765, Play, Clientbound, "ClientboundBlockAction", 0x09);
    reg!(767, Play, Clientbound, "ClientboundBlockAction", 0x09);
    reg!(5, Play, Clientbound, "ClientboundBlockUpdate", 0x23);
    reg!(47, Play, Clientbound, "ClientboundBlockUpdate", 0x23);
    reg!(340, Play, Clientbound, "ClientboundBlockUpdate", 0x0B);
    reg!(762, Play, Clientbound, "ClientboundBlockUpdate", 0x0A);
    reg!(765, Play, Clientbound, "ClientboundBlockUpdate", 0x0A);
    reg!(767, Play, Clientbound, "ClientboundBlockUpdate", 0x0A);
    reg!(340, Play, Clientbound, "ClientboundBossBar", 0x0C);
    reg!(762, Play, Clientbound, "ClientboundBossBar", 0x0B);
    reg!(765, Play, Clientbound, "ClientboundBossBar", 0x0A);
    reg!(767, Play, Clientbound, "ClientboundBossBar", 0x0B);
    reg!(5, Play, Clientbound, "ClientboundSpawnMob", 0x0F);

    reg!(5, Play, Clientbound, "ClientboundChangeDifficulty", 0x41);
    reg!(47, Play, Clientbound, "ClientboundChangeDifficulty", 0x41);
    reg!(340, Play, Clientbound, "ClientboundChangeDifficulty", 0x0D);
    reg!(762, Play, Clientbound, "ClientboundChangeDifficulty", 0x0C);
    reg!(765, Play, Clientbound, "ClientboundChangeDifficulty", 0x0C);
    reg!(767, Play, Clientbound, "ClientboundChangeDifficulty", 0x0C);
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundChunkBatchFinished",
        0x0D
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundChunkBatchFinished",
        0x0D
    );
    reg!(765, Play, Clientbound, "ClientboundChunkBatchStart", 0x0E);
    reg!(767, Play, Clientbound, "ClientboundChunkBatchStart", 0x0E);
    reg!(762, Play, Clientbound, "ClientboundChunkBiomes", 0x0D);
    reg!(765, Play, Clientbound, "ClientboundChunkBiomes", 0x0F);
    reg!(767, Play, Clientbound, "ClientboundChunkBiomes", 0x0F);
    reg!(762, Play, Clientbound, "ClientboundClearTitles", 0x0E);
    reg!(765, Play, Clientbound, "ClientboundClearTitles", 0x10);
    reg!(767, Play, Clientbound, "ClientboundClearTitles", 0x10);
    reg!(5, Play, Clientbound, "ClientboundCommandSuggestions", 0x3A);
    reg!(47, Play, Clientbound, "ClientboundCommandSuggestions", 0x3A);
    reg!(
        340,
        Play,
        Clientbound,
        "ClientboundCommandSuggestions",
        0x0E
    );
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundCommandSuggestions",
        0x0F
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundCommandSuggestions",
        0x11
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundCommandSuggestions",
        0x11
    );
    reg!(762, Play, Clientbound, "ClientboundCommands", 0x10);
    reg!(765, Play, Clientbound, "ClientboundCommands", 0x12);
    reg!(767, Play, Clientbound, "ClientboundCommands", 0x12);
    reg!(5, Play, Clientbound, "ClientboundContainerClose", 0x2E);
    reg!(47, Play, Clientbound, "ClientboundContainerClose", 0x2E);
    reg!(340, Play, Clientbound, "ClientboundContainerClose", 0x12);
    reg!(762, Play, Clientbound, "ClientboundContainerClose", 0x11);
    reg!(765, Play, Clientbound, "ClientboundContainerClose", 0x13);
    reg!(767, Play, Clientbound, "ClientboundContainerClose", 0x13);
    reg!(5, Play, Clientbound, "ClientboundContainerSetContent", 0x30);
    reg!(
        47,
        Play,
        Clientbound,
        "ClientboundContainerSetContent",
        0x30
    );
    reg!(
        340,
        Play,
        Clientbound,
        "ClientboundContainerSetContent",
        0x14
    );
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundContainerSetContent",
        0x12
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundContainerSetContent",
        0x14
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundContainerSetContent",
        0x14
    );
    reg!(
        5,
        Play,
        Clientbound,
        "ClientboundContainerSetProperty",
        0x31
    );
    reg!(
        47,
        Play,
        Clientbound,
        "ClientboundContainerSetProperty",
        0x31
    );
    reg!(
        340,
        Play,
        Clientbound,
        "ClientboundContainerSetProperty",
        0x15
    );
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundContainerSetProperty",
        0x13
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundContainerSetProperty",
        0x15
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundContainerSetProperty",
        0x15
    );
    reg!(5, Play, Clientbound, "ClientboundContainerSetSlot", 0x2F);
    reg!(47, Play, Clientbound, "ClientboundContainerSetSlot", 0x2F);
    reg!(340, Play, Clientbound, "ClientboundContainerSetSlot", 0x16);
    reg!(762, Play, Clientbound, "ClientboundContainerSetSlot", 0x14);
    reg!(765, Play, Clientbound, "ClientboundContainerSetSlot", 0x16);
    reg!(767, Play, Clientbound, "ClientboundContainerSetSlot", 0x16);
    reg!(767, Play, Clientbound, "ClientboundCookieRequest", 0x17);
    reg!(340, Play, Clientbound, "ClientboundCooldown", 0x17);
    reg!(762, Play, Clientbound, "ClientboundCooldown", 0x15);
    reg!(765, Play, Clientbound, "ClientboundCooldown", 0x17);
    reg!(767, Play, Clientbound, "ClientboundCooldown", 0x18);
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundCustomChatCompletions",
        0x16
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundCustomChatCompletions",
        0x18
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundCustomChatCompletions",
        0x19
    );
    reg!(5, Play, Clientbound, "ClientboundCustomPayload", 0x3F);
    reg!(5, Play, Clientbound, "ClientboundPluginMessage", 0x3F);
    reg!(47, Play, Clientbound, "ClientboundCustomPayload", 0x3F);
    reg!(47, Play, Clientbound, "ClientboundPluginMessage", 0x3F);
    reg!(340, Play, Clientbound, "ClientboundPluginMessage", 0x18);
    reg!(762, Play, Clientbound, "ClientboundCustomPayload", 0x17);
    reg!(762, Play, Clientbound, "ClientboundPluginMessage", 0x17);
    reg!(765, Play, Clientbound, "ClientboundCustomPayload", 0x18);
    reg!(765, Play, Clientbound, "ClientboundPluginMessage", 0x18);
    reg!(767, Play, Clientbound, "ClientboundCustomPayload", 0x1A);
    reg!(767, Play, Clientbound, "ClientboundPluginMessage", 0x1A);
    reg!(762, Play, Clientbound, "ClientboundDamageEvent", 0x18);
    reg!(765, Play, Clientbound, "ClientboundDamageEvent", 0x19);
    reg!(767, Play, Clientbound, "ClientboundDamageEvent", 0x1B);
    reg!(767, Play, Clientbound, "ClientboundDebugSample", 0x1C);
    reg!(762, Play, Clientbound, "ClientboundDeleteChat", 0x19);
    reg!(765, Play, Clientbound, "ClientboundDeleteChat", 0x1A);
    reg!(767, Play, Clientbound, "ClientboundDeleteChat", 0x1D);
    reg!(5, Play, Clientbound, "ClientboundDisconnect", 0x40);
    reg!(47, Play, Clientbound, "ClientboundDisconnect", 0x40);
    reg!(340, Play, Clientbound, "ClientboundDisconnect", 0x1A);
    reg!(762, Play, Clientbound, "ClientboundDisconnect", 0x1A);
    reg!(765, Play, Clientbound, "ClientboundDisconnect", 0x1B);
    reg!(767, Play, Clientbound, "ClientboundDisconnect", 0x1E);
    reg!(762, Play, Clientbound, "ClientboundDisguisedChat", 0x1B);
    reg!(765, Play, Clientbound, "ClientboundDisguisedChat", 0x1C);
    reg!(767, Play, Clientbound, "ClientboundDisguisedChat", 0x1F);
    reg!(5, Play, Clientbound, "ClientboundEntityEvent", 0x1A);
    reg!(47, Play, Clientbound, "ClientboundEntityEvent", 0x1A);
    reg!(340, Play, Clientbound, "ClientboundEntityEvent", 0x1B);
    reg!(762, Play, Clientbound, "ClientboundEntityEvent", 0x1C);
    reg!(765, Play, Clientbound, "ClientboundEntityEvent", 0x1D);
    reg!(767, Play, Clientbound, "ClientboundEntityEvent", 0x20);
    reg!(5, Play, Clientbound, "ClientboundExplosion", 0x27);
    reg!(47, Play, Clientbound, "ClientboundExplosion", 0x27);
    reg!(340, Play, Clientbound, "ClientboundExplosion", 0x1C);
    reg!(762, Play, Clientbound, "ClientboundExplosion", 0x1D);
    reg!(765, Play, Clientbound, "ClientboundExplosion", 0x1E);
    reg!(767, Play, Clientbound, "ClientboundExplosion", 0x21);
    reg!(5, Play, Clientbound, "ClientboundForgetLevelChunk", 0x26);
    reg!(47, Play, Clientbound, "ClientboundForgetLevelChunk", 0x26);
    reg!(340, Play, Clientbound, "ClientboundForgetLevelChunk", 0x22);
    reg!(762, Play, Clientbound, "ClientboundForgetLevelChunk", 0x1E);
    reg!(765, Play, Clientbound, "ClientboundForgetLevelChunk", 0x1F);
    reg!(767, Play, Clientbound, "ClientboundForgetLevelChunk", 0x22);
    reg!(5, Play, Clientbound, "ClientboundGameEvent", 0x2B);
    reg!(47, Play, Clientbound, "ClientboundGameEvent", 0x2B);
    reg!(340, Play, Clientbound, "ClientboundGameEvent", 0x1E);
    reg!(762, Play, Clientbound, "ClientboundGameEvent", 0x1F);
    reg!(765, Play, Clientbound, "ClientboundGameEvent", 0x20);
    reg!(767, Play, Clientbound, "ClientboundGameEvent", 0x23);
    reg!(340, Play, Clientbound, "ClientboundHorseScreenOpen", 0x1F);
    reg!(762, Play, Clientbound, "ClientboundHorseScreenOpen", 0x20);
    reg!(765, Play, Clientbound, "ClientboundHorseScreenOpen", 0x21);
    reg!(767, Play, Clientbound, "ClientboundHorseScreenOpen", 0x24);
    reg!(762, Play, Clientbound, "ClientboundHurtAnimation", 0x21);
    reg!(765, Play, Clientbound, "ClientboundHurtAnimation", 0x22);
    reg!(767, Play, Clientbound, "ClientboundHurtAnimation", 0x25);
    reg!(47, Play, Clientbound, "ClientboundInitializeBorder", 0x44);
    reg!(340, Play, Clientbound, "ClientboundInitializeBorder", 0x38);
    reg!(762, Play, Clientbound, "ClientboundInitializeBorder", 0x22);
    reg!(765, Play, Clientbound, "ClientboundInitializeBorder", 0x23);
    reg!(767, Play, Clientbound, "ClientboundInitializeBorder", 0x26);
    reg!(5, Play, Clientbound, "ClientboundKeepAlive", 0x00);
    reg!(47, Play, Clientbound, "ClientboundKeepAlive", 0x00);
    reg!(340, Play, Clientbound, "ClientboundKeepAlive", 0x1F);
    reg!(762, Play, Clientbound, "ClientboundKeepAlive", 0x24);
    reg!(765, Play, Clientbound, "ClientboundKeepAlive", 0x26);
    reg!(767, Play, Clientbound, "ClientboundKeepAlive", 0x29);
    reg!(5, Play, Clientbound, "ClientboundLevelChunkWithLight", 0x21);
    reg!(
        47,
        Play,
        Clientbound,
        "ClientboundLevelChunkWithLight",
        0x21
    );
    reg!(
        340,
        Play,
        Clientbound,
        "ClientboundLevelChunkWithLight",
        0x20
    );
    reg!(340, Play, Clientbound, "SPacketChunkData", 0x20);
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundLevelChunkWithLight",
        0x25
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundLevelChunkWithLight",
        0x27
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundLevelChunkWithLight",
        0x2A
    );
    reg!(5, Play, Clientbound, "ClientboundLevelEvent", 0x28);
    reg!(47, Play, Clientbound, "ClientboundLevelEvent", 0x28);
    reg!(340, Play, Clientbound, "ClientboundLevelEvent", 0x21);
    reg!(762, Play, Clientbound, "ClientboundLevelEvent", 0x26);
    reg!(765, Play, Clientbound, "ClientboundLevelEvent", 0x28);
    reg!(767, Play, Clientbound, "ClientboundLevelEvent", 0x2B);
    reg!(5, Play, Clientbound, "ClientboundLevelParticles", 0x2A);
    reg!(47, Play, Clientbound, "ClientboundLevelParticles", 0x2A);
    reg!(762, Play, Clientbound, "ClientboundLevelParticles", 0x27);
    reg!(765, Play, Clientbound, "ClientboundLevelParticles", 0x29);
    reg!(767, Play, Clientbound, "ClientboundLevelParticles", 0x2C);
    reg!(762, Play, Clientbound, "ClientboundLightUpdate", 0x28);
    reg!(765, Play, Clientbound, "ClientboundLightUpdate", 0x2A);
    reg!(767, Play, Clientbound, "ClientboundLightUpdate", 0x2D);
    reg!(5, Play, Clientbound, "ClientboundLoginPlay", 0x01);
    reg!(5, Play, Clientbound, "ClientboundJoinGame", 0x01);
    reg!(5, Play, Clientbound, "ClientboundLogin", 0x01);
    reg!(47, Play, Clientbound, "ClientboundLoginPlay", 0x01);
    reg!(47, Play, Clientbound, "ClientboundJoinGame", 0x01);
    reg!(47, Play, Clientbound, "ClientboundLogin", 0x01);
    reg!(340, Play, Clientbound, "ClientboundLoginPlay", 0x23);
    reg!(340, Play, Clientbound, "ClientboundJoinGame", 0x23);
    reg!(340, Play, Clientbound, "ClientboundLogin", 0x23);
    reg!(762, Play, Clientbound, "ClientboundLoginPlay", 0x29);
    reg!(762, Play, Clientbound, "ClientboundJoinGame", 0x29);
    reg!(762, Play, Clientbound, "ClientboundLogin", 0x29);
    reg!(765, Play, Clientbound, "ClientboundLoginPlay", 0x2B);
    reg!(765, Play, Clientbound, "ClientboundJoinGame", 0x2B);
    reg!(765, Play, Clientbound, "ClientboundLogin", 0x2B);
    reg!(767, Play, Clientbound, "ClientboundLoginPlay", 0x2E);
    reg!(767, Play, Clientbound, "ClientboundJoinGame", 0x2E);
    reg!(767, Play, Clientbound, "ClientboundLogin", 0x2E);
    reg!(5, Play, Clientbound, "ClientboundMapItemData", 0x34);
    reg!(47, Play, Clientbound, "ClientboundMapItemData", 0x34);
    reg!(340, Play, Clientbound, "ClientboundMapItemData", 0x24);
    reg!(762, Play, Clientbound, "ClientboundMapItemData", 0x2A);
    reg!(765, Play, Clientbound, "ClientboundMapItemData", 0x2C);
    reg!(767, Play, Clientbound, "ClientboundMapItemData", 0x2F);
    reg!(762, Play, Clientbound, "ClientboundMerchantOffers", 0x2B);
    reg!(765, Play, Clientbound, "ClientboundMerchantOffers", 0x2D);
    reg!(767, Play, Clientbound, "ClientboundMerchantOffers", 0x30);
    reg!(5, Play, Clientbound, "ClientboundMoveEntityPos", 0x15);
    reg!(47, Play, Clientbound, "ClientboundMoveEntityPos", 0x15);
    reg!(340, Play, Clientbound, "ClientboundMoveEntityPos", 0x26);
    reg!(762, Play, Clientbound, "ClientboundMoveEntityPos", 0x2C);
    reg!(765, Play, Clientbound, "ClientboundMoveEntityPos", 0x2E);
    reg!(767, Play, Clientbound, "ClientboundMoveEntityPos", 0x31);
    reg!(5, Play, Clientbound, "ClientboundMoveEntityPosRot", 0x17);
    reg!(47, Play, Clientbound, "ClientboundMoveEntityPosRot", 0x17);
    reg!(340, Play, Clientbound, "ClientboundMoveEntityPosRot", 0x27);
    reg!(762, Play, Clientbound, "ClientboundMoveEntityPosRot", 0x2D);
    reg!(765, Play, Clientbound, "ClientboundMoveEntityPosRot", 0x2F);
    reg!(767, Play, Clientbound, "ClientboundMoveEntityPosRot", 0x32);
    reg!(5, Play, Clientbound, "ClientboundMoveEntityRot", 0x16);
    reg!(47, Play, Clientbound, "ClientboundMoveEntityRot", 0x16);
    reg!(340, Play, Clientbound, "ClientboundMoveEntityRot", 0x28);
    reg!(762, Play, Clientbound, "ClientboundMoveEntityRot", 0x2E);
    reg!(765, Play, Clientbound, "ClientboundMoveEntityRot", 0x30);
    reg!(767, Play, Clientbound, "ClientboundMoveEntityRot", 0x33);
    reg!(340, Play, Clientbound, "ClientboundMoveVehicle", 0x29);
    reg!(762, Play, Clientbound, "ClientboundMoveVehicle", 0x2F);
    reg!(765, Play, Clientbound, "ClientboundMoveVehicle", 0x31);
    reg!(767, Play, Clientbound, "ClientboundMoveVehicle", 0x34);
    reg!(762, Play, Clientbound, "ClientboundOpenBook", 0x30);
    reg!(765, Play, Clientbound, "ClientboundOpenBook", 0x32);
    reg!(767, Play, Clientbound, "ClientboundOpenBook", 0x35);
    reg!(5, Play, Clientbound, "ClientboundOpenScreen", 0x2D);
    reg!(47, Play, Clientbound, "ClientboundOpenScreen", 0x2D);
    reg!(340, Play, Clientbound, "ClientboundOpenScreen", 0x13);
    reg!(762, Play, Clientbound, "ClientboundOpenScreen", 0x31);
    reg!(765, Play, Clientbound, "ClientboundOpenScreen", 0x33);
    reg!(767, Play, Clientbound, "ClientboundOpenScreen", 0x36);
    reg!(5, Play, Clientbound, "ClientboundOpenSignEditor", 0x36);
    reg!(47, Play, Clientbound, "ClientboundOpenSignEditor", 0x36);
    reg!(340, Play, Clientbound, "ClientboundOpenSignEditor", 0x2A);
    reg!(762, Play, Clientbound, "ClientboundOpenSignEditor", 0x32);
    reg!(765, Play, Clientbound, "ClientboundOpenSignEditor", 0x34);
    reg!(767, Play, Clientbound, "ClientboundOpenSignEditor", 0x37);
    reg!(762, Play, Clientbound, "ClientboundPing", 0x33);
    reg!(765, Play, Clientbound, "ClientboundPing", 0x35);
    reg!(767, Play, Clientbound, "ClientboundPing", 0x38);
    reg!(340, Play, Clientbound, "ClientboundPlaceGhostRecipe", 0x31);
    reg!(762, Play, Clientbound, "ClientboundPlaceGhostRecipe", 0x35);
    reg!(765, Play, Clientbound, "ClientboundPlaceGhostRecipe", 0x37);
    reg!(767, Play, Clientbound, "ClientboundPlaceGhostRecipe", 0x3A);
    reg!(5, Play, Clientbound, "ClientboundPlayerAbilities", 0x39);
    reg!(47, Play, Clientbound, "ClientboundPlayerAbilities", 0x39);
    reg!(340, Play, Clientbound, "ClientboundPlayerAbilities", 0x2C);
    reg!(762, Play, Clientbound, "ClientboundPlayerAbilities", 0x36);
    reg!(765, Play, Clientbound, "ClientboundPlayerAbilities", 0x38);
    reg!(767, Play, Clientbound, "ClientboundPlayerAbilities", 0x3B);
    reg!(762, Play, Clientbound, "ClientboundPlayerChat", 0x37);
    reg!(765, Play, Clientbound, "ClientboundPlayerChat", 0x39);
    reg!(767, Play, Clientbound, "ClientboundPlayerChat", 0x3C);
    reg!(5, Play, Clientbound, "ClientboundPlayerCombatEnd", 0x42);
    reg!(47, Play, Clientbound, "ClientboundPlayerCombatEnd", 0x42);
    reg!(340, Play, Clientbound, "ClientboundPlayerCombatEnd", 0x33);
    reg!(762, Play, Clientbound, "ClientboundPlayerCombatEnd", 0x38);
    reg!(765, Play, Clientbound, "ClientboundPlayerCombatEnd", 0x3A);
    reg!(767, Play, Clientbound, "ClientboundPlayerCombatEnd", 0x3D);
    reg!(5, Play, Clientbound, "ClientboundPlayerCombatEnter", 0x42);
    reg!(47, Play, Clientbound, "ClientboundPlayerCombatEnter", 0x42);
    reg!(340, Play, Clientbound, "ClientboundPlayerCombatEnter", 0x33);
    reg!(762, Play, Clientbound, "ClientboundPlayerCombatEnter", 0x39);
    reg!(765, Play, Clientbound, "ClientboundPlayerCombatEnter", 0x3B);
    reg!(767, Play, Clientbound, "ClientboundPlayerCombatEnter", 0x3E);
    reg!(5, Play, Clientbound, "ClientboundPlayerCombatKill", 0x42);
    reg!(47, Play, Clientbound, "ClientboundPlayerCombatKill", 0x42);
    reg!(340, Play, Clientbound, "ClientboundPlayerCombatKill", 0x33);
    reg!(762, Play, Clientbound, "ClientboundPlayerCombatKill", 0x3A);
    reg!(765, Play, Clientbound, "ClientboundPlayerCombatKill", 0x3C);
    reg!(767, Play, Clientbound, "ClientboundPlayerCombatKill", 0x3F);
    reg!(762, Play, Clientbound, "ClientboundPlayerInfoRemove", 0x3B);
    reg!(765, Play, Clientbound, "ClientboundPlayerInfoRemove", 0x3D);
    reg!(767, Play, Clientbound, "ClientboundPlayerInfoRemove", 0x40);
    reg!(5, Play, Clientbound, "ClientboundPlayerInfoUpdate", 0x38);
    reg!(47, Play, Clientbound, "ClientboundPlayerInfoUpdate", 0x38);
    reg!(340, Play, Clientbound, "ClientboundPlayerInfoUpdate", 0x2E);
    reg!(762, Play, Clientbound, "ClientboundPlayerInfoUpdate", 0x3C);
    reg!(765, Play, Clientbound, "ClientboundPlayerInfoUpdate", 0x3E);
    reg!(767, Play, Clientbound, "ClientboundPlayerInfoUpdate", 0x41);
    reg!(762, Play, Clientbound, "ClientboundPlayerLookAt", 0x3D);
    reg!(765, Play, Clientbound, "ClientboundPlayerLookAt", 0x3F);
    reg!(767, Play, Clientbound, "ClientboundPlayerLookAt", 0x42);
    reg!(5, Play, Clientbound, "ClientboundPlayerPosition", 0x08);
    reg!(47, Play, Clientbound, "ClientboundPlayerPosition", 0x08);
    reg!(762, Play, Clientbound, "ClientboundPlayerPosition", 0x3E);
    reg!(765, Play, Clientbound, "ClientboundPlayerPosition", 0x40);
    reg!(767, Play, Clientbound, "ClientboundPlayerPosition", 0x43);
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundRecipeBookSettings",
        0x3F
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundRecipeBookSettings",
        0x41
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundRecipeBookSettings",
        0x44
    );
    reg!(340, Play, Clientbound, "ClientboundRecipes", 0x34);
    reg!(762, Play, Clientbound, "ClientboundRecipes", 0x40);
    reg!(765, Play, Clientbound, "ClientboundRecipes", 0x42);
    reg!(767, Play, Clientbound, "ClientboundRecipes", 0x45);
    reg!(5, Play, Clientbound, "ClientboundRemoveEntities", 0x13);
    reg!(47, Play, Clientbound, "ClientboundRemoveEntities", 0x13);
    reg!(340, Play, Clientbound, "ClientboundRemoveEntities", 0x32);
    reg!(762, Play, Clientbound, "ClientboundRemoveEntities", 0x41);
    reg!(765, Play, Clientbound, "ClientboundRemoveEntities", 0x43);
    reg!(767, Play, Clientbound, "ClientboundRemoveEntities", 0x46);
    reg!(5, Play, Clientbound, "ClientboundRemoveEntityEffect", 0x1E);
    reg!(47, Play, Clientbound, "ClientboundRemoveEntityEffect", 0x1E);
    reg!(
        340,
        Play,
        Clientbound,
        "ClientboundRemoveEntityEffect",
        0x36
    );
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundRemoveEntityEffect",
        0x42
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundRemoveEntityEffect",
        0x44
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundRemoveEntityEffect",
        0x47
    );
    reg!(5, Play, Clientbound, "ClientboundResetScore", 0x3B);
    reg!(47, Play, Clientbound, "ClientboundResetScore", 0x3B);
    reg!(340, Play, Clientbound, "ClientboundResetScore", 0x4C);
    reg!(767, Play, Clientbound, "ClientboundResetScore", 0x48);
    reg!(765, Play, Clientbound, "ClientboundResourcePackPop", 0x46);
    reg!(767, Play, Clientbound, "ClientboundResourcePackPop", 0x49);
    reg!(5, Play, Clientbound, "ClientboundResourcePackPush", 0x48);
    reg!(47, Play, Clientbound, "ClientboundResourcePackPush", 0x48);
    reg!(340, Play, Clientbound, "ClientboundResourcePackPush", 0x3A);
    reg!(762, Play, Clientbound, "ClientboundResourcePackPush", 0x43);
    reg!(765, Play, Clientbound, "ClientboundResourcePackPush", 0x47);
    reg!(767, Play, Clientbound, "ClientboundResourcePackPush", 0x4A);
    reg!(5, Play, Clientbound, "ClientboundRespawn", 0x07);
    reg!(47, Play, Clientbound, "ClientboundRespawn", 0x07);
    reg!(340, Play, Clientbound, "ClientboundRespawn", 0x35);
    reg!(762, Play, Clientbound, "ClientboundRespawn", 0x44);
    reg!(765, Play, Clientbound, "ClientboundRespawn", 0x48);
    reg!(767, Play, Clientbound, "ClientboundRespawn", 0x4B);
    reg!(5, Play, Clientbound, "ClientboundRotateHead", 0x19);
    reg!(47, Play, Clientbound, "ClientboundRotateHead", 0x19);
    reg!(340, Play, Clientbound, "ClientboundRotateHead", 0x36);
    reg!(762, Play, Clientbound, "ClientboundRotateHead", 0x45);
    reg!(765, Play, Clientbound, "ClientboundRotateHead", 0x49);
    reg!(767, Play, Clientbound, "ClientboundRotateHead", 0x4C);
    reg!(5, Play, Clientbound, "ClientboundSectionBlocksUpdate", 0x22);
    reg!(
        47,
        Play,
        Clientbound,
        "ClientboundSectionBlocksUpdate",
        0x22
    );
    reg!(
        340,
        Play,
        Clientbound,
        "ClientboundSectionBlocksUpdate",
        0x10
    );
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundSectionBlocksUpdate",
        0x46
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundSectionBlocksUpdate",
        0x4A
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundSectionBlocksUpdate",
        0x4D
    );
    reg!(
        340,
        Play,
        Clientbound,
        "ClientboundSelectAdvancementsTab",
        0x37
    );
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundSelectAdvancementsTab",
        0x47
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundSelectAdvancementsTab",
        0x4B
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundSelectAdvancementsTab",
        0x4E
    );
    reg!(762, Play, Clientbound, "ClientboundServerData", 0x48);
    reg!(765, Play, Clientbound, "ClientboundServerData", 0x4C);
    reg!(767, Play, Clientbound, "ClientboundServerData", 0x4F);
    reg!(762, Play, Clientbound, "ClientboundSetActionBarText", 0x49);
    reg!(765, Play, Clientbound, "ClientboundSetActionBarText", 0x4D);
    reg!(767, Play, Clientbound, "ClientboundSetActionBarText", 0x50);
    reg!(47, Play, Clientbound, "ClientboundSetBorderCenter", 0x44);
    reg!(340, Play, Clientbound, "ClientboundSetBorderCenter", 0x38);
    reg!(762, Play, Clientbound, "ClientboundSetBorderCenter", 0x4A);
    reg!(765, Play, Clientbound, "ClientboundSetBorderCenter", 0x4E);
    reg!(767, Play, Clientbound, "ClientboundSetBorderCenter", 0x51);
    reg!(47, Play, Clientbound, "ClientboundSetBorderLerpSize", 0x44);
    reg!(340, Play, Clientbound, "ClientboundSetBorderLerpSize", 0x38);
    reg!(762, Play, Clientbound, "ClientboundSetBorderLerpSize", 0x4B);
    reg!(765, Play, Clientbound, "ClientboundSetBorderLerpSize", 0x4F);
    reg!(767, Play, Clientbound, "ClientboundSetBorderLerpSize", 0x52);
    reg!(47, Play, Clientbound, "ClientboundSetBorderSize", 0x44);
    reg!(340, Play, Clientbound, "ClientboundSetBorderSize", 0x38);
    reg!(762, Play, Clientbound, "ClientboundSetBorderSize", 0x4C);
    reg!(765, Play, Clientbound, "ClientboundSetBorderSize", 0x50);
    reg!(767, Play, Clientbound, "ClientboundSetBorderSize", 0x53);
    reg!(
        47,
        Play,
        Clientbound,
        "ClientboundSetBorderWarningDelay",
        0x44
    );
    reg!(
        340,
        Play,
        Clientbound,
        "ClientboundSetBorderWarningDelay",
        0x38
    );
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundSetBorderWarningDelay",
        0x4D
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundSetBorderWarningDelay",
        0x51
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundSetBorderWarningDelay",
        0x54
    );
    reg!(
        47,
        Play,
        Clientbound,
        "ClientboundSetBorderWarningDistance",
        0x44
    );
    reg!(
        340,
        Play,
        Clientbound,
        "ClientboundSetBorderWarningDistance",
        0x38
    );
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundSetBorderWarningDistance",
        0x4E
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundSetBorderWarningDistance",
        0x52
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundSetBorderWarningDistance",
        0x55
    );
    reg!(47, Play, Clientbound, "ClientboundSetCamera", 0x43);
    reg!(340, Play, Clientbound, "ClientboundSetCamera", 0x39);
    reg!(762, Play, Clientbound, "ClientboundSetCamera", 0x4F);
    reg!(765, Play, Clientbound, "ClientboundSetCamera", 0x53);
    reg!(767, Play, Clientbound, "ClientboundSetCamera", 0x56);
    reg!(767, Play, Clientbound, "ClientboundSetCursorItem", 0x57);
    reg!(5, Play, Clientbound, "ClientboundSetEntityLink", 0x1B);
    reg!(47, Play, Clientbound, "ClientboundSetEntityLink", 0x1B);
    reg!(340, Play, Clientbound, "ClientboundSetEntityLink", 0x3F);
    reg!(762, Play, Clientbound, "ClientboundSetEntityLink", 0x50);
    reg!(765, Play, Clientbound, "ClientboundSetEntityLink", 0x54);
    reg!(767, Play, Clientbound, "ClientboundSetEntityLink", 0x58);
    reg!(5, Play, Clientbound, "ClientboundSetEntityMotion", 0x12);
    reg!(47, Play, Clientbound, "ClientboundSetEntityMotion", 0x12);
    reg!(340, Play, Clientbound, "ClientboundSetEntityMotion", 0x3D);
    reg!(762, Play, Clientbound, "ClientboundSetEntityMotion", 0x51);
    reg!(765, Play, Clientbound, "ClientboundSetEntityMotion", 0x55);
    reg!(767, Play, Clientbound, "ClientboundSetEntityMotion", 0x59);
    reg!(5, Play, Clientbound, "ClientboundSetEquipment", 0x04);
    reg!(47, Play, Clientbound, "ClientboundSetEquipment", 0x04);
    reg!(340, Play, Clientbound, "ClientboundSetEquipment", 0x3F);
    reg!(762, Play, Clientbound, "ClientboundSetEquipment", 0x52);
    reg!(765, Play, Clientbound, "ClientboundSetEquipment", 0x56);
    reg!(767, Play, Clientbound, "ClientboundSetEquipment", 0x5A);
    reg!(5, Play, Clientbound, "ClientboundSetExperience", 0x1F);
    reg!(47, Play, Clientbound, "ClientboundSetExperience", 0x1F);
    reg!(340, Play, Clientbound, "ClientboundSetExperience", 0x40);
    reg!(762, Play, Clientbound, "ClientboundSetExperience", 0x53);
    reg!(765, Play, Clientbound, "ClientboundSetExperience", 0x57);
    reg!(767, Play, Clientbound, "ClientboundSetExperience", 0x5B);
    reg!(5, Play, Clientbound, "ClientboundSetHealth", 0x06);
    reg!(47, Play, Clientbound, "ClientboundSetHealth", 0x06);
    reg!(340, Play, Clientbound, "ClientboundSetHealth", 0x41);
    reg!(762, Play, Clientbound, "ClientboundSetHealth", 0x54);
    reg!(765, Play, Clientbound, "ClientboundSetHealth", 0x58);
    reg!(767, Play, Clientbound, "ClientboundSetHealth", 0x5C);
    reg!(5, Play, Clientbound, "ClientboundSetHeldItem", 0x09);
    reg!(5, Play, Clientbound, "ClientboundSetCarriedItem", 0x09);
    reg!(47, Play, Clientbound, "ClientboundSetHeldItem", 0x09);
    reg!(47, Play, Clientbound, "ClientboundSetCarriedItem", 0x09);
    reg!(340, Play, Clientbound, "ClientboundSetHeldItem", 0x3A);
    reg!(340, Play, Clientbound, "ClientboundSetCarriedItem", 0x3A);
    reg!(762, Play, Clientbound, "ClientboundSetHeldItem", 0x4A);
    reg!(762, Play, Clientbound, "ClientboundSetCarriedItem", 0x4A);
    reg!(765, Play, Clientbound, "ClientboundSetHeldItem", 0x4C);
    reg!(765, Play, Clientbound, "ClientboundSetCarriedItem", 0x4C);
    reg!(767, Play, Clientbound, "ClientboundSetHeldItem", 0x5D);
    reg!(767, Play, Clientbound, "ClientboundSetCarriedItem", 0x5D);
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundSetPlayerInventory",
        0x5E
    );
    reg!(
        5,
        Play,
        Clientbound,
        "ClientboundSetScoreboardObjective",
        0x3B
    );
    reg!(
        47,
        Play,
        Clientbound,
        "ClientboundSetScoreboardObjective",
        0x3B
    );
    reg!(
        340,
        Play,
        Clientbound,
        "ClientboundSetScoreboardObjective",
        0x42
    );
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundSetScoreboardObjective",
        0x55
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundSetScoreboardObjective",
        0x59
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundSetScoreboardObjective",
        0x5F
    );
    reg!(5, Play, Clientbound, "ClientboundSetScoreboardScore", 0x3C);
    reg!(47, Play, Clientbound, "ClientboundSetScoreboardScore", 0x3C);
    reg!(
        340,
        Play,
        Clientbound,
        "ClientboundSetScoreboardScore",
        0x44
    );
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundSetScoreboardScore",
        0x56
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundSetScoreboardScore",
        0x5A
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundSetScoreboardScore",
        0x60
    );
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundSetSimulationDistance",
        0x57
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundSetSimulationDistance",
        0x5B
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundSetSimulationDistance",
        0x61
    );
    reg!(762, Play, Clientbound, "ClientboundSetSubtitleText", 0x58);
    reg!(765, Play, Clientbound, "ClientboundSetSubtitleText", 0x5C);
    reg!(767, Play, Clientbound, "ClientboundSetSubtitleText", 0x62);
    reg!(5, Play, Clientbound, "ClientboundSetTime", 0x03);
    reg!(47, Play, Clientbound, "ClientboundSetTime", 0x03);
    reg!(340, Play, Clientbound, "ClientboundSetTime", 0x47);
    reg!(762, Play, Clientbound, "ClientboundSetTime", 0x59);
    reg!(765, Play, Clientbound, "ClientboundSetTime", 0x5D);
    reg!(767, Play, Clientbound, "ClientboundSetTime", 0x63);
    reg!(762, Play, Clientbound, "ClientboundSetTitleText", 0x5A);
    reg!(765, Play, Clientbound, "ClientboundSetTitleText", 0x5E);
    reg!(767, Play, Clientbound, "ClientboundSetTitleText", 0x64);
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundSetTitleAnimationTimes",
        0x5B
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundSetTitleAnimationTimes",
        0x5F
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundSetTitleAnimationTimes",
        0x65
    );
    reg!(762, Play, Clientbound, "ClientboundSoundEntity", 0x5C);
    reg!(765, Play, Clientbound, "ClientboundSoundEntity", 0x60);
    reg!(767, Play, Clientbound, "ClientboundSoundEntity", 0x66);
    reg!(5, Play, Clientbound, "ClientboundSound", 0x29);
    reg!(47, Play, Clientbound, "ClientboundSound", 0x29);
    reg!(340, Play, Clientbound, "ClientboundSound", 0x49);
    reg!(762, Play, Clientbound, "ClientboundSound", 0x5D);
    reg!(765, Play, Clientbound, "ClientboundSound", 0x61);
    reg!(767, Play, Clientbound, "ClientboundSound", 0x67);
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundStartConfiguration",
        0x62
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundStartConfiguration",
        0x68
    );
    reg!(340, Play, Clientbound, "ClientboundStopSound", 0x4A);
    reg!(762, Play, Clientbound, "ClientboundStopSound", 0x5E);
    reg!(765, Play, Clientbound, "ClientboundStopSound", 0x63);
    reg!(767, Play, Clientbound, "ClientboundStopSound", 0x69);
    reg!(767, Play, Clientbound, "ClientboundStoreCookie", 0x6A);
    reg!(5, Play, Clientbound, "ClientboundSystemChat", 0x02);
    reg!(5, Play, Clientbound, "ClientboundChatMessage", 0x02);
    reg!(47, Play, Clientbound, "ClientboundSystemChat", 0x02);
    reg!(47, Play, Clientbound, "ClientboundChatMessage", 0x02);
    reg!(340, Play, Clientbound, "ClientboundSystemChat", 0x0F);
    reg!(340, Play, Clientbound, "ClientboundChatMessage", 0x0F);
    reg!(762, Play, Clientbound, "ClientboundSystemChat", 0x62);
    reg!(762, Play, Clientbound, "ClientboundChatMessage", 0x62);
    reg!(765, Play, Clientbound, "ClientboundSystemChat", 0x64);
    reg!(765, Play, Clientbound, "ClientboundChatMessage", 0x64);
    reg!(767, Play, Clientbound, "ClientboundSystemChat", 0x6B);
    reg!(767, Play, Clientbound, "ClientboundChatMessage", 0x6B);
    reg!(5, Play, Clientbound, "ClientboundTabList", 0x47);
    reg!(47, Play, Clientbound, "ClientboundTabList", 0x47);
    reg!(340, Play, Clientbound, "ClientboundTabList", 0x4A);
    reg!(762, Play, Clientbound, "ClientboundTabList", 0x63);
    reg!(765, Play, Clientbound, "ClientboundTabList", 0x65);
    reg!(767, Play, Clientbound, "ClientboundTabList", 0x6C);
    reg!(762, Play, Clientbound, "ClientboundTagQuery", 0x64);
    reg!(765, Play, Clientbound, "ClientboundTagQuery", 0x66);
    reg!(767, Play, Clientbound, "ClientboundTagQuery", 0x6D);
    reg!(5, Play, Clientbound, "ClientboundTakeItemEntity", 0x0D);
    reg!(47, Play, Clientbound, "ClientboundTakeItemEntity", 0x0D);
    reg!(340, Play, Clientbound, "ClientboundTakeItemEntity", 0x4B);
    reg!(762, Play, Clientbound, "ClientboundTakeItemEntity", 0x65);
    reg!(765, Play, Clientbound, "ClientboundTakeItemEntity", 0x67);
    reg!(767, Play, Clientbound, "ClientboundTakeItemEntity", 0x6E);
    reg!(5, Play, Clientbound, "ClientboundTeleportEntity", 0x18);
    reg!(47, Play, Clientbound, "ClientboundTeleportEntity", 0x18);
    reg!(340, Play, Clientbound, "ClientboundTeleportEntity", 0x4C);
    reg!(762, Play, Clientbound, "ClientboundTeleportEntity", 0x66);
    reg!(765, Play, Clientbound, "ClientboundTeleportEntity", 0x68);
    reg!(767, Play, Clientbound, "ClientboundTeleportEntity", 0x6F);
    reg!(765, Play, Clientbound, "ClientboundTickingState", 0x69);
    reg!(767, Play, Clientbound, "ClientboundTickingState", 0x70);
    reg!(765, Play, Clientbound, "ClientboundTickingStep", 0x6A);
    reg!(767, Play, Clientbound, "ClientboundTickingStep", 0x71);
    reg!(767, Play, Clientbound, "ClientboundTransfer", 0x72);
    reg!(
        340,
        Play,
        Clientbound,
        "ClientboundUpdateAdvancements",
        0x4E
    );
    reg!(
        762,
        Play,
        Clientbound,
        "ClientboundUpdateAdvancements",
        0x67
    );
    reg!(
        765,
        Play,
        Clientbound,
        "ClientboundUpdateAdvancements",
        0x6B
    );
    reg!(
        767,
        Play,
        Clientbound,
        "ClientboundUpdateAdvancements",
        0x73
    );
    reg!(5, Play, Clientbound, "ClientboundUpdateAttributes", 0x20);
    reg!(47, Play, Clientbound, "ClientboundUpdateAttributes", 0x20);
    reg!(340, Play, Clientbound, "ClientboundUpdateAttributes", 0x4F);
    reg!(762, Play, Clientbound, "ClientboundUpdateAttributes", 0x68);
    reg!(765, Play, Clientbound, "ClientboundUpdateAttributes", 0x6C);
    reg!(767, Play, Clientbound, "ClientboundUpdateAttributes", 0x74);
    reg!(5, Play, Clientbound, "ClientboundUpdateEffects", 0x1D);
    reg!(47, Play, Clientbound, "ClientboundUpdateEffects", 0x1D);
    reg!(340, Play, Clientbound, "ClientboundUpdateEffects", 0x51);
    reg!(762, Play, Clientbound, "ClientboundUpdateEffects", 0x69);
    reg!(765, Play, Clientbound, "ClientboundUpdateEffects", 0x6D);
    reg!(767, Play, Clientbound, "ClientboundUpdateEffects", 0x75);
    reg!(762, Play, Clientbound, "ClientboundUpdateRecipes", 0x6A);
    reg!(765, Play, Clientbound, "ClientboundUpdateRecipes", 0x6E);
    reg!(767, Play, Clientbound, "ClientboundUpdateRecipes", 0x76);
    reg!(762, Play, Clientbound, "ClientboundUpdateTags", 0x6B);
    reg!(765, Play, Clientbound, "ClientboundUpdateTags", 0x6F);
    reg!(767, Play, Clientbound, "ClientboundUpdateTags", 0x77);

    reg!(340, Play, Serverbound, "ServerboundTeleportConfirm", 0x00);
    reg!(
        340,
        Play,
        Serverbound,
        "ServerboundAcceptTeleportation",
        0x00
    );
    reg!(762, Play, Serverbound, "ServerboundTeleportConfirm", 0x00);
    reg!(
        762,
        Play,
        Serverbound,
        "ServerboundAcceptTeleportation",
        0x00
    );
    reg!(765, Play, Serverbound, "ServerboundTeleportConfirm", 0x00);
    reg!(
        765,
        Play,
        Serverbound,
        "ServerboundAcceptTeleportation",
        0x00
    );
    reg!(767, Play, Serverbound, "ServerboundTeleportConfirm", 0x00);
    reg!(
        767,
        Play,
        Serverbound,
        "ServerboundAcceptTeleportation",
        0x00
    );
    reg!(
        5,
        Play,
        Serverbound,
        "ServerboundMovePlayerStatusOnly",
        0x03
    );
    reg!(
        47,
        Play,
        Serverbound,
        "ServerboundMovePlayerStatusOnly",
        0x03
    );
    reg!(
        340,
        Play,
        Serverbound,
        "ServerboundMovePlayerStatusOnly",
        0x0C
    );
    reg!(
        762,
        Play,
        Serverbound,
        "ServerboundMovePlayerStatusOnly",
        0x13
    );
    reg!(
        765,
        Play,
        Serverbound,
        "ServerboundMovePlayerStatusOnly",
        0x15
    );
    reg!(
        767,
        Play,
        Serverbound,
        "ServerboundMovePlayerStatusOnly",
        0x16
    );
    reg!(5, Play, Serverbound, "ServerboundMovePlayerPos", 0x04);
    reg!(47, Play, Serverbound, "ServerboundMovePlayerPos", 0x04);
    reg!(340, Play, Serverbound, "ServerboundMovePlayerPos", 0x0D);
    reg!(762, Play, Serverbound, "ServerboundMovePlayerPos", 0x14);
    reg!(765, Play, Serverbound, "ServerboundMovePlayerPos", 0x16);
    reg!(767, Play, Serverbound, "ServerboundMovePlayerPos", 0x17);
    reg!(5, Play, Serverbound, "ServerboundMovePlayerPosRot", 0x06);
    reg!(47, Play, Serverbound, "ServerboundMovePlayerPosRot", 0x06);
    reg!(340, Play, Serverbound, "ServerboundMovePlayerPosRot", 0x0F);
    reg!(762, Play, Serverbound, "ServerboundMovePlayerPosRot", 0x16);
    reg!(765, Play, Serverbound, "ServerboundMovePlayerPosRot", 0x18);
    reg!(767, Play, Serverbound, "ServerboundMovePlayerPosRot", 0x19);
    reg!(5, Play, Serverbound, "ServerboundMovePlayerRot", 0x05);
    reg!(47, Play, Serverbound, "ServerboundMovePlayerRot", 0x05);
    reg!(340, Play, Serverbound, "ServerboundMovePlayerRot", 0x0E);
    reg!(762, Play, Serverbound, "ServerboundMovePlayerRot", 0x15);
    reg!(765, Play, Serverbound, "ServerboundMovePlayerRot", 0x17);
    reg!(767, Play, Serverbound, "ServerboundMovePlayerRot", 0x18);
    reg!(340, Play, Serverbound, "ServerboundVehicleMove", 0x10);
    reg!(762, Play, Serverbound, "ServerboundVehicleMove", 0x17);
    reg!(765, Play, Serverbound, "ServerboundVehicleMove", 0x19);
    reg!(767, Play, Serverbound, "ServerboundVehicleMove", 0x1A);
    reg!(340, Play, Serverbound, "ServerboundSteerBoat", 0x11);
    reg!(762, Play, Serverbound, "ServerboundSteerBoat", 0x18);
    reg!(765, Play, Serverbound, "ServerboundSteerBoat", 0x1A);
    reg!(767, Play, Serverbound, "ServerboundSteerBoat", 0x1B);
    reg!(5, Play, Serverbound, "ServerboundPlayerAbilities", 0x13);
    reg!(47, Play, Serverbound, "ServerboundPlayerAbilities", 0x13);
    reg!(340, Play, Serverbound, "ServerboundPlayerAbilities", 0x13);
    reg!(762, Play, Serverbound, "ServerboundPlayerAbilities", 0x1B);
    reg!(765, Play, Serverbound, "ServerboundPlayerAbilities", 0x1D);
    reg!(767, Play, Serverbound, "ServerboundPlayerAbilities", 0x1E);
    reg!(5, Play, Serverbound, "ServerboundPlayerAction", 0x07);
    reg!(47, Play, Serverbound, "ServerboundPlayerAction", 0x07);
    reg!(340, Play, Serverbound, "ServerboundPlayerAction", 0x14);
    reg!(762, Play, Serverbound, "ServerboundPlayerAction", 0x1C);
    reg!(765, Play, Serverbound, "ServerboundPlayerAction", 0x1E);
    reg!(767, Play, Serverbound, "ServerboundPlayerAction", 0x1F);
    reg!(5, Play, Serverbound, "ServerboundEntityAction", 0x0B);
    reg!(47, Play, Serverbound, "ServerboundEntityAction", 0x0B);
    reg!(340, Play, Serverbound, "ServerboundEntityAction", 0x15);
    reg!(762, Play, Serverbound, "ServerboundEntityAction", 0x1D);
    reg!(765, Play, Serverbound, "ServerboundEntityAction", 0x1F);
    reg!(767, Play, Serverbound, "ServerboundEntityAction", 0x20);
    reg!(5, Play, Serverbound, "ServerboundSteerVehicle", 0x0C);
    reg!(47, Play, Serverbound, "ServerboundSteerVehicle", 0x0C);
    reg!(340, Play, Serverbound, "ServerboundSteerVehicle", 0x16);
    reg!(762, Play, Serverbound, "ServerboundSteerVehicle", 0x1E);
    reg!(765, Play, Serverbound, "ServerboundSteerVehicle", 0x20);
    reg!(767, Play, Serverbound, "ServerboundSteerVehicle", 0x21);
    reg!(5, Play, Serverbound, "ServerboundInteract", 0x02);
    reg!(47, Play, Serverbound, "ServerboundInteract", 0x02);
    reg!(340, Play, Serverbound, "ServerboundInteract", 0x0A);
    reg!(762, Play, Serverbound, "ServerboundInteract", 0x11);
    reg!(765, Play, Serverbound, "ServerboundInteract", 0x13);
    reg!(767, Play, Serverbound, "ServerboundInteract", 0x14);
    reg!(
        767,
        Play,
        Serverbound,
        "ServerboundPlayerWeaponAttack",
        0x22
    );
    reg!(5, Play, Serverbound, "ServerboundAnimation", 0x0A);
    reg!(5, Play, Serverbound, "ServerboundSwingArm", 0x0A);
    reg!(47, Play, Serverbound, "ServerboundAnimation", 0x0A);
    reg!(47, Play, Serverbound, "ServerboundSwingArm", 0x0A);
    reg!(340, Play, Serverbound, "ServerboundAnimation", 0x1D);
    reg!(340, Play, Serverbound, "ServerboundSwingArm", 0x1D);
    reg!(762, Play, Serverbound, "ServerboundAnimation", 0x2C);
    reg!(762, Play, Serverbound, "ServerboundSwingArm", 0x2C);
    reg!(765, Play, Serverbound, "ServerboundAnimation", 0x2E);
    reg!(765, Play, Serverbound, "ServerboundSwingArm", 0x2E);
    reg!(767, Play, Serverbound, "ServerboundAnimation", 0x32);
    reg!(767, Play, Serverbound, "ServerboundSwingArm", 0x32);
    reg!(47, Play, Serverbound, "ServerboundSpectate", 0x18);
    reg!(340, Play, Serverbound, "ServerboundSpectate", 0x1E);
    reg!(762, Play, Serverbound, "ServerboundSpectate", 0x2D);
    reg!(765, Play, Serverbound, "ServerboundSpectate", 0x2F);
    reg!(767, Play, Serverbound, "ServerboundSpectate", 0x33);
    reg!(
        5,
        Play,
        Serverbound,
        "ServerboundPlayerBlockPlacement",
        0x08
    );
    reg!(5, Play, Serverbound, "ServerboundUseItemOn", 0x08);
    reg!(
        47,
        Play,
        Serverbound,
        "ServerboundPlayerBlockPlacement",
        0x08
    );
    reg!(47, Play, Serverbound, "ServerboundUseItemOn", 0x08);
    reg!(
        340,
        Play,
        Serverbound,
        "ServerboundPlayerBlockPlacement",
        0x1F
    );
    reg!(340, Play, Serverbound, "ServerboundUseItemOn", 0x1F);
    reg!(
        762,
        Play,
        Serverbound,
        "ServerboundPlayerBlockPlacement",
        0x2E
    );
    reg!(762, Play, Serverbound, "ServerboundUseItemOn", 0x2E);
    reg!(
        765,
        Play,
        Serverbound,
        "ServerboundPlayerBlockPlacement",
        0x30
    );
    reg!(765, Play, Serverbound, "ServerboundUseItemOn", 0x30);
    reg!(
        767,
        Play,
        Serverbound,
        "ServerboundPlayerBlockPlacement",
        0x34
    );
    reg!(767, Play, Serverbound, "ServerboundUseItemOn", 0x34);
    reg!(340, Play, Serverbound, "ServerboundUseItem", 0x20);
    reg!(762, Play, Serverbound, "ServerboundUseItem", 0x2F);
    reg!(765, Play, Serverbound, "ServerboundUseItem", 0x31);
    reg!(767, Play, Serverbound, "ServerboundUseItem", 0x35);
    reg!(5, Play, Serverbound, "ServerboundCloseWindow", 0x0D);
    reg!(47, Play, Serverbound, "ServerboundCloseWindow", 0x0D);
    reg!(340, Play, Serverbound, "ServerboundCloseWindow", 0x08);
    reg!(762, Play, Serverbound, "ServerboundCloseWindow", 0x0B);
    reg!(765, Play, Serverbound, "ServerboundCloseWindow", 0x0C);
    reg!(767, Play, Serverbound, "ServerboundCloseWindow", 0x0E);
    reg!(5, Play, Serverbound, "ServerboundClickWindow", 0x0E);
    reg!(47, Play, Serverbound, "ServerboundClickWindow", 0x0E);
    reg!(340, Play, Serverbound, "ServerboundClickWindow", 0x07);
    reg!(762, Play, Serverbound, "ServerboundClickWindow", 0x0A);
    reg!(765, Play, Serverbound, "ServerboundClickWindow", 0x0B);
    reg!(767, Play, Serverbound, "ServerboundClickWindow", 0x0D);
    reg!(5, Play, Serverbound, "ServerboundClickWindowButton", 0x11);
    reg!(47, Play, Serverbound, "ServerboundClickWindowButton", 0x11);
    reg!(340, Play, Serverbound, "ServerboundClickWindowButton", 0x06);
    reg!(762, Play, Serverbound, "ServerboundClickWindowButton", 0x09);
    reg!(765, Play, Serverbound, "ServerboundClickWindowButton", 0x0A);
    reg!(767, Play, Serverbound, "ServerboundClickWindowButton", 0x0C);
    reg!(
        5,
        Play,
        Serverbound,
        "ServerboundCreativeInventoryAction",
        0x10
    );
    reg!(
        47,
        Play,
        Serverbound,
        "ServerboundCreativeInventoryAction",
        0x10
    );
    reg!(
        340,
        Play,
        Serverbound,
        "ServerboundCreativeInventoryAction",
        0x1B
    );
    reg!(
        762,
        Play,
        Serverbound,
        "ServerboundCreativeInventoryAction",
        0x28
    );
    reg!(
        765,
        Play,
        Serverbound,
        "ServerboundCreativeInventoryAction",
        0x2A
    );
    reg!(
        767,
        Play,
        Serverbound,
        "ServerboundCreativeInventoryAction",
        0x2E
    );
    reg!(5, Play, Serverbound, "ServerboundHeldItemChange", 0x09);
    reg!(47, Play, Serverbound, "ServerboundHeldItemChange", 0x09);
    reg!(340, Play, Serverbound, "ServerboundHeldItemChange", 0x1A);
    reg!(762, Play, Serverbound, "ServerboundHeldItemChange", 0x25);
    reg!(765, Play, Serverbound, "ServerboundHeldItemChange", 0x27);
    reg!(767, Play, Serverbound, "ServerboundHeldItemChange", 0x2B);
    reg!(
        767,
        Play,
        Serverbound,
        "ServerboundSetCreativeModeSlot",
        0x2C
    );
    reg!(5, Play, Serverbound, "ServerboundKeepAlive", 0x00);
    reg!(47, Play, Serverbound, "ServerboundKeepAlive", 0x00);
    reg!(340, Play, Serverbound, "ServerboundKeepAlive", 0x0B);
    reg!(762, Play, Serverbound, "ServerboundKeepAlive", 0x12);
    reg!(765, Play, Serverbound, "ServerboundKeepAlive", 0x14);
    reg!(767, Play, Serverbound, "ServerboundKeepAlive", 0x15);
    reg!(5, Play, Serverbound, "ServerboundChatMessage", 0x01);
    reg!(47, Play, Serverbound, "ServerboundChatMessage", 0x01);
    reg!(340, Play, Serverbound, "ServerboundChatMessage", 0x02);
    reg!(762, Play, Serverbound, "ServerboundChatMessage", 0x04);
    reg!(765, Play, Serverbound, "ServerboundChatMessage", 0x05);
    reg!(767, Play, Serverbound, "ServerboundChatMessage", 0x06);
    reg!(762, Play, Serverbound, "ServerboundChatCommand", 0x03);
    reg!(765, Play, Serverbound, "ServerboundChatCommand", 0x04);
    reg!(767, Play, Serverbound, "ServerboundChatCommand", 0x05);
    reg!(762, Play, Serverbound, "ServerboundChatSessionUpdate", 0x05);
    reg!(765, Play, Serverbound, "ServerboundChatSessionUpdate", 0x06);
    reg!(767, Play, Serverbound, "ServerboundChatSessionUpdate", 0x07);
    reg!(5, Play, Serverbound, "ServerboundClientStatus", 0x16);
    reg!(47, Play, Serverbound, "ServerboundClientStatus", 0x16);
    reg!(340, Play, Serverbound, "ServerboundClientStatus", 0x03);
    reg!(762, Play, Serverbound, "ServerboundClientStatus", 0x06);
    reg!(765, Play, Serverbound, "ServerboundClientStatus", 0x07);
    reg!(767, Play, Serverbound, "ServerboundClientStatus", 0x08);
    reg!(5, Play, Serverbound, "ServerboundClientSettings", 0x15);
    reg!(5, Play, Serverbound, "ServerboundClientInformation", 0x15);
    reg!(47, Play, Serverbound, "ServerboundClientSettings", 0x15);
    reg!(47, Play, Serverbound, "ServerboundClientInformation", 0x15);
    reg!(340, Play, Serverbound, "ServerboundClientSettings", 0x04);
    reg!(340, Play, Serverbound, "ServerboundClientInformation", 0x04);
    reg!(762, Play, Serverbound, "ServerboundClientSettings", 0x07);
    reg!(762, Play, Serverbound, "ServerboundClientInformation", 0x07);
    reg!(765, Play, Serverbound, "ServerboundClientSettings", 0x08);
    reg!(765, Play, Serverbound, "ServerboundClientInformation", 0x08);
    reg!(767, Play, Serverbound, "ServerboundClientSettings", 0x09);
    reg!(767, Play, Serverbound, "ServerboundClientInformation", 0x09);
    reg!(5, Play, Serverbound, "ServerboundPluginMessage", 0x17);
    reg!(47, Play, Serverbound, "ServerboundPluginMessage", 0x17);
    reg!(340, Play, Serverbound, "ServerboundPluginMessage", 0x09);
    reg!(762, Play, Serverbound, "ServerboundPluginMessage", 0x0C);
    reg!(765, Play, Serverbound, "ServerboundPluginMessage", 0x0D);
    reg!(767, Play, Serverbound, "ServerboundPluginMessage", 0x0F);
    reg!(5, Play, Serverbound, "ServerboundResourcePackStatus", 0x19);
    reg!(47, Play, Serverbound, "ServerboundResourcePackStatus", 0x19);
    reg!(
        340,
        Play,
        Serverbound,
        "ServerboundResourcePackStatus",
        0x19
    );
    reg!(
        762,
        Play,
        Serverbound,
        "ServerboundResourcePackStatus",
        0x24
    );
    reg!(
        765,
        Play,
        Serverbound,
        "ServerboundResourcePackStatus",
        0x26
    );
    reg!(
        767,
        Play,
        Serverbound,
        "ServerboundResourcePackStatus",
        0x2A
    );
    reg!(762, Play, Serverbound, "ServerboundPong", 0x20);
    reg!(765, Play, Serverbound, "ServerboundPong", 0x22);
    reg!(767, Play, Serverbound, "ServerboundPong", 0x24);
    reg!(
        765,
        Play,
        Serverbound,
        "ServerboundConfigurationAcknowledged",
        0x0B
    );
    reg!(
        767,
        Play,
        Serverbound,
        "ServerboundConfigurationAcknowledged",
        0x0B
    );
    reg!(767, Play, Serverbound, "ServerboundButtonPressed", 0x0C);
    reg!(5, Play, Serverbound, "ServerboundCommandSuggestion", 0x14);
    reg!(47, Play, Serverbound, "ServerboundCommandSuggestion", 0x14);
    reg!(340, Play, Serverbound, "ServerboundCommandSuggestion", 0x01);
    reg!(762, Play, Serverbound, "ServerboundCommandSuggestion", 0x09);
    reg!(765, Play, Serverbound, "ServerboundCommandSuggestion", 0x09);
    reg!(767, Play, Serverbound, "ServerboundCommandSuggestion", 0x0A);
    reg!(762, Play, Serverbound, "ServerboundDifficultyChange", 0x02);
    reg!(765, Play, Serverbound, "ServerboundDifficultyChange", 0x02);
    reg!(767, Play, Serverbound, "ServerboundDifficultyChange", 0x02);
    reg!(762, Play, Serverbound, "ServerboundDifficultyLock", 0x10);
    reg!(765, Play, Serverbound, "ServerboundDifficultyLock", 0x11);
    reg!(767, Play, Serverbound, "ServerboundDifficultyLock", 0x12);
    reg!(762, Play, Serverbound, "ServerboundEditBook", 0x0D);
    reg!(765, Play, Serverbound, "ServerboundEditBook", 0x0E);
    reg!(767, Play, Serverbound, "ServerboundEditBook", 0x10);
    reg!(762, Play, Serverbound, "ServerboundEntityTagQuery", 0x0E);
    reg!(765, Play, Serverbound, "ServerboundEntityTagQuery", 0x0F);
    reg!(767, Play, Serverbound, "ServerboundEntityTagQuery", 0x11);
    reg!(762, Play, Serverbound, "ServerboundJigsawGenerate", 0x0F);
    reg!(765, Play, Serverbound, "ServerboundJigsawGenerate", 0x10);
    reg!(767, Play, Serverbound, "ServerboundJigsawGenerate", 0x13);
    reg!(762, Play, Serverbound, "ServerboundPaddleBoat", 0x18);
    reg!(765, Play, Serverbound, "ServerboundPaddleBoat", 0x1A);
    reg!(767, Play, Serverbound, "ServerboundPaddleBoat", 0x1B);
    reg!(340, Play, Serverbound, "ServerboundPickItem", 0x12);
    reg!(762, Play, Serverbound, "ServerboundPickItem", 0x19);
    reg!(765, Play, Serverbound, "ServerboundPickItem", 0x1B);
    reg!(767, Play, Serverbound, "ServerboundPickItem", 0x1C);
    reg!(340, Play, Serverbound, "ServerboundPlaceRecipe", 0x13);
    reg!(762, Play, Serverbound, "ServerboundPlaceRecipe", 0x1A);
    reg!(765, Play, Serverbound, "ServerboundPlaceRecipe", 0x1C);
    reg!(767, Play, Serverbound, "ServerboundPlaceRecipe", 0x1D);
    reg!(
        340,
        Play,
        Serverbound,
        "ServerboundRecipeBookChangeSettings",
        0x17
    );
    reg!(
        762,
        Play,
        Serverbound,
        "ServerboundRecipeBookChangeSettings",
        0x21
    );
    reg!(
        765,
        Play,
        Serverbound,
        "ServerboundRecipeBookChangeSettings",
        0x23
    );
    reg!(
        767,
        Play,
        Serverbound,
        "ServerboundRecipeBookChangeSettings",
        0x26
    );
    reg!(
        340,
        Play,
        Serverbound,
        "ServerboundRecipeBookSeenRecipe",
        0x18
    );
    reg!(
        762,
        Play,
        Serverbound,
        "ServerboundRecipeBookSeenRecipe",
        0x22
    );
    reg!(
        765,
        Play,
        Serverbound,
        "ServerboundRecipeBookSeenRecipe",
        0x24
    );
    reg!(
        767,
        Play,
        Serverbound,
        "ServerboundRecipeBookSeenRecipe",
        0x27
    );
    reg!(762, Play, Serverbound, "ServerboundRenameItem", 0x23);
    reg!(765, Play, Serverbound, "ServerboundRenameItem", 0x25);
    reg!(767, Play, Serverbound, "ServerboundRenameItem", 0x29);
    reg!(340, Play, Serverbound, "ServerboundSelectTrade", 0x1C);
    reg!(762, Play, Serverbound, "ServerboundSelectTrade", 0x26);
    reg!(765, Play, Serverbound, "ServerboundSelectTrade", 0x28);
    reg!(767, Play, Serverbound, "ServerboundSelectTrade", 0x2D);
    reg!(340, Play, Serverbound, "ServerboundSetBeaconEffect", 0x1A);
    reg!(762, Play, Serverbound, "ServerboundSetBeaconEffect", 0x27);
    reg!(765, Play, Serverbound, "ServerboundSetBeaconEffect", 0x29);
    reg!(767, Play, Serverbound, "ServerboundSetBeaconEffect", 0x2F);
    reg!(340, Play, Serverbound, "ServerboundSetStructureBlock", 0x21);
    reg!(762, Play, Serverbound, "ServerboundSetStructureBlock", 0x30);
    reg!(765, Play, Serverbound, "ServerboundSetStructureBlock", 0x32);
    reg!(767, Play, Serverbound, "ServerboundSetStructureBlock", 0x36);
    reg!(767, Play, Serverbound, "ServerboundSetMerchantTrade", 0x2D);
    reg!(
        340,
        Play,
        Serverbound,
        "ServerboundUpdateCommandBlock",
        0x22
    );
    reg!(
        762,
        Play,
        Serverbound,
        "ServerboundUpdateCommandBlock",
        0x2A
    );
    reg!(
        765,
        Play,
        Serverbound,
        "ServerboundUpdateCommandBlock",
        0x2C
    );
    reg!(
        767,
        Play,
        Serverbound,
        "ServerboundUpdateCommandBlock",
        0x30
    );
    reg!(
        340,
        Play,
        Serverbound,
        "ServerboundUpdateCommandBlockMinecart",
        0x23
    );
    reg!(
        762,
        Play,
        Serverbound,
        "ServerboundUpdateCommandBlockMinecart",
        0x2B
    );
    reg!(
        765,
        Play,
        Serverbound,
        "ServerboundUpdateCommandBlockMinecart",
        0x2D
    );
    reg!(
        767,
        Play,
        Serverbound,
        "ServerboundUpdateCommandBlockMinecart",
        0x31
    );
    reg!(5, Play, Serverbound, "ServerboundUpdateSign", 0x12);
    reg!(47, Play, Serverbound, "ServerboundUpdateSign", 0x12);
    reg!(340, Play, Serverbound, "ServerboundUpdateSign", 0x1C);
    reg!(762, Play, Serverbound, "ServerboundUpdateSign", 0x2A);
    reg!(765, Play, Serverbound, "ServerboundUpdateSign", 0x33);
    reg!(767, Play, Serverbound, "ServerboundUpdateSign", 0x37);
    reg!(5, Play, Serverbound, "ServerboundConfirmTransaction", 0x0F);
    reg!(47, Play, Serverbound, "ServerboundConfirmTransaction", 0x0F);
    reg!(
        340,
        Play,
        Serverbound,
        "ServerboundConfirmTransaction",
        0x05
    );
    reg!(5, Play, Serverbound, "ServerboundEnchantItem", 0x11);
    reg!(47, Play, Serverbound, "ServerboundEnchantItem", 0x11);

    reg!(340, Play, Serverbound, "ServerboundEnchantItem", 0x06);
    reg!(340, Play, Serverbound, "ServerboundChatMessage", 0x02);
    reg!(340, Play, Serverbound, "ServerboundCustomPayload", 0x0A);
    reg!(340, Play, Clientbound, "ClientboundCustomPayload", 0x18);
    reg!(340, Play, Clientbound, "ClientboundPlayerPosition", 0x2F);
    reg!(340, Play, Clientbound, "ClientboundLevelParticles", 0x22);
    reg!(340, Play, Clientbound, "ClientboundSpawnEntity", 0x00);
    reg!(
        340,
        Play,
        Clientbound,
        "ClientboundSpawnExperienceOrb",
        0x01
    );
    reg!(340, Play, Clientbound, "ClientboundSpawnGlobalEntity", 0x02);
    reg!(340, Play, Clientbound, "ClientboundSpawnMob", 0x03);
    reg!(340, Play, Clientbound, "ClientboundSpawnPainting", 0x04);
    reg!(340, Play, Clientbound, "ClientboundSpawnPlayer", 0x05);

    reg!(
        340,
        Login,
        Clientbound,
        "ClientboundLoginPluginRequest",
        0xFF
    );
    reg!(
        340,
        Login,
        Serverbound,
        "ServerboundLoginPluginResponse",
        0xFF
    );
    reg!(
        340,
        Login,
        Serverbound,
        "ServerboundLoginAcknowledged",
        0xFF
    );
    reg!(
        340,
        Configuration,
        Serverbound,
        "AcknowledgeFinishConfiguration",
        0xFF
    );

    r
}
