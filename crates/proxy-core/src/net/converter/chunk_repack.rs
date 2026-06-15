//! Chunk repack across the 1.13 flattening + 1.14 biome/storage rewrites.
//!
//! Handles conversion of chunk data between different Minecraft versions,
//! including the 1.13 flattening (block/item ID changes) and 1.14 biome/storage rewrites.

use bytes::{Buf, BufMut, BytesMut};
use kojacoord_protocol::{
    types::{
        BiomeConverter, BlockStateConverter, ChunkData, ChunkFormat, FlattenedChunkSection,
        LegacyChunkSection, ModernBiomeChunkSection, NewHeightChunkSection,
    },
    Epoch, ProtocolVersion,
};
use std::io::{Cursor, Read};

/// Map a wire protocol to the chunk format its clients expect. `Unknown`
/// epoch collapses to Legacy as a "safe" default — repacking a chunk
/// the wrong way is preferable to dropping it.
pub fn chunk_format_for_version(version: ProtocolVersion) -> ChunkFormat {
    match version.epoch() {
        Epoch::PreNetty | Epoch::V1_7 | Epoch::V1_8 | Epoch::V1_9_To_1_12 => ChunkFormat::Legacy,
        Epoch::V1_13_To_1_15 => ChunkFormat::Flattened,
        Epoch::V1_16 | Epoch::V1_17_To_1_18 => ChunkFormat::ModernBiomes,
        Epoch::V1_19 | Epoch::V1_20 | Epoch::V1_21Plus => ChunkFormat::NewHeight,
        Epoch::Unknown => ChunkFormat::Legacy,
    }
}

/// Translates `LevelChunkWithLight` packet bodies between the four
/// chunk formats. Owns the block + biome conversion tables so they're
/// loaded once and shared across every chunk passing through.
pub struct ChunkRepacker {
    block_converter: BlockStateConverter,
    biome_converter: BiomeConverter,
}

impl ChunkRepacker {
    pub fn new() -> Self {
        Self {
            block_converter: BlockStateConverter::new(),
            biome_converter: BiomeConverter::new(),
        }
    }

    /// Borrow the biome conversion table. Callers crossing the
    /// 1.15→1.16 boundary use this to translate the 256 i32 biome array
    /// into the 1.16+ string-keyed registry palette before repacking the
    /// chunk body.
    pub fn biome_converter(&self) -> &BiomeConverter {
        &self.biome_converter
    }

    /// Borrow the block-state conversion table. Cross-version chunk repack
    /// goes through this to map legacy `(id, meta)` pairs to flattened
    /// state ids when stitching 1.12.2 → 1.13+ chunk sections.
    pub fn block_converter(&self) -> &BlockStateConverter {
        &self.block_converter
    }

    fn bits_per_block_for_palette(palette_len: usize) -> usize {
        let bpb = 4.max(palette_len.next_power_of_two().trailing_zeros() as usize);
        if bpb <= 4 {
            4
        } else if bpb <= 8 {
            8
        } else {
            bpb
        }
    }

    /// Repack chunk data from one version to another
    pub fn repack(
        &self,
        chunk_data: &[u8],
        from_version: ProtocolVersion,
        to_version: ProtocolVersion,
    ) -> Result<Vec<u8>, String> {
        let from_format = chunk_format_for_version(from_version);
        let to_format = chunk_format_for_version(to_version);

        if from_format == to_format {
            // No conversion needed
            return Ok(chunk_data.to_vec());
        }

        tracing::debug!(
            from = ?from_format,
            to = ?to_format,
            "Repacking chunk data"
        );

        // Parse source chunk data
        let source_chunk = self.parse_chunk(chunk_data, from_format)?;

        // Convert to target format
        let target_chunk = self.convert_chunk(source_chunk, from_format, to_format)?;

        // Encode target chunk data
        self.encode_chunk(&target_chunk, to_format)
    }

    /// Check if chunk repacking is needed between two versions
    pub fn needs_repack(from_version: ProtocolVersion, to_version: ProtocolVersion) -> bool {
        chunk_format_for_version(from_version) != chunk_format_for_version(to_version)
    }

    /// Parse chunk data based on format
    fn parse_chunk(&self, data: &[u8], format: ChunkFormat) -> Result<ChunkData, String> {
        match format {
            ChunkFormat::Legacy => self.parse_legacy_chunk(data),
            ChunkFormat::Flattened => self.parse_flattened_chunk(data),
            ChunkFormat::ModernBiomes => self.parse_modern_biome_chunk(data),
            ChunkFormat::NewHeight => self.parse_new_height_chunk(data),
        }
    }

    /// Parse legacy chunk (pre-1.13)
    fn parse_legacy_chunk(&self, data: &[u8]) -> Result<ChunkData, String> {
        let mut cursor = Cursor::new(data);
        let mut sections = Vec::new();

        let bitmask = cursor.get_u16_le();

        for i in 0..16 {
            if (bitmask & (1 << i)) != 0 {
                let mut section = LegacyChunkSection::new();

                // Read block IDs (4096 bytes)
                cursor
                    .read_exact(&mut section.blocks)
                    .map_err(|e| format!("Failed to read block IDs: {}", e))?;

                // Read block metadata (2048 bytes, 4 bits per block)
                cursor
                    .read_exact(&mut section.metadata)
                    .map_err(|e| format!("Failed to read block metadata: {}", e))?;

                // Read block light (2048 bytes)
                cursor
                    .read_exact(&mut section.block_light)
                    .map_err(|e| format!("Failed to read block light: {}", e))?;

                // Read sky light (2048 bytes)
                cursor
                    .read_exact(&mut section.sky_light)
                    .map_err(|e| format!("Failed to read sky light: {}", e))?;

                sections.push(section);
            }
        }

        Ok(ChunkData::Legacy(sections))
    }

    /// Parse flattened chunk (1.13+)
    fn parse_flattened_chunk(&self, data: &[u8]) -> Result<ChunkData, String> {
        let mut cursor = Cursor::new(data);
        let mut sections = Vec::new();

        let bitmask = cursor.get_u16_le();

        for i in 0..16 {
            if (bitmask & (1 << i)) != 0 {
                let mut section = FlattenedChunkSection::new();

                // Read block states (variable length)
                let bits_per_block = cursor.get_u8();
                let palette_len = cursor.get_u16_le() as usize;

                // Read palette
                for _ in 0..palette_len {
                    let len = cursor.get_u16_le() as usize;
                    let mut name = vec![0u8; len];
                    cursor
                        .read_exact(&mut name)
                        .map_err(|e| format!("Failed to read palette entry: {}", e))?;
                    section.palette.push(
                        String::from_utf8(name)
                            .map_err(|e| format!("Invalid UTF-8 in palette: {}", e))?,
                    );
                }

                let data_len = cursor.get_u32_le() as usize;
                if data_len > 16_777_216 {
                    return Err(format!(
                        "Block state data too large: {data_len} bytes (max 16 MiB)"
                    ));
                }
                if data_len > cursor.remaining() {
                    return Err(format!(
                        "Block state data ({data_len} bytes) exceeds remaining buffer ({} bytes)",
                        cursor.remaining()
                    ));
                }
                let mut block_state_data = vec![0u8; data_len];
                cursor
                    .read_exact(&mut block_state_data)
                    .map_err(|e| format!("Failed to read block state data: {}", e))?;

                let mut block_state_cursor = Cursor::new(block_state_data);
                let long_count = (4096 * bits_per_block as usize).div_ceil(64);
                for _ in 0..long_count {
                    section.block_states.push(block_state_cursor.get_i64_le());
                }

                cursor
                    .read_exact(&mut section.block_light)
                    .map_err(|e| format!("Failed to read block light: {}", e))?;
                cursor
                    .read_exact(&mut section.sky_light)
                    .map_err(|e| format!("Failed to read sky light: {}", e))?;

                sections.push(section);
            }
        }

        Ok(ChunkData::Flattened(sections))
    }

    /// Parse modern biome chunk (1.14+)
    fn parse_modern_biome_chunk(&self, data: &[u8]) -> Result<ChunkData, String> {
        let flattened = self.parse_flattened_chunk(data)?;

        match flattened {
            ChunkData::Flattened(sections) => {
                let mut modern_sections = Vec::new();
                for section in sections {
                    let modern = ModernBiomeChunkSection {
                        block_states: section,
                        biomes: vec![0; 256], // Default to ocean
                    };
                    modern_sections.push(modern);
                }
                Ok(ChunkData::ModernBiomes(modern_sections))
            },
            _ => Err("Expected flattened chunk".into()),
        }
    }

    /// Parse new height chunk (1.18+)
    fn parse_new_height_chunk(&self, data: &[u8]) -> Result<ChunkData, String> {
        let mut cursor = Cursor::new(data);
        let mut sections = Vec::new();

        let bitmask = cursor.get_i32_le();

        for i in 0..24 {
            if (bitmask & (1 << i)) != 0 {
                let mut section = NewHeightChunkSection::new();

                // Read block states (similar to flattened)
                let bits_per_block = cursor.get_u8();
                let palette_len = cursor.get_u16_le() as usize;

                for _ in 0..palette_len {
                    let len = cursor.get_u16_le() as usize;
                    let mut name = vec![0u8; len];
                    cursor
                        .read_exact(&mut name)
                        .map_err(|e| format!("Failed to read palette entry: {}", e))?;
                    section.block_states.palette.push(
                        String::from_utf8(name)
                            .map_err(|e| format!("Invalid UTF-8 in palette: {}", e))?,
                    );
                }

                let data_len = cursor.get_u32_le() as usize;
                if data_len > 16_777_216 {
                    return Err(format!(
                        "Block state data too large: {data_len} bytes (max 16 MiB)"
                    ));
                }
                if data_len > cursor.remaining() {
                    return Err(format!(
                        "Block state data ({data_len} bytes) exceeds remaining buffer ({} bytes)",
                        cursor.remaining()
                    ));
                }
                let mut block_state_data = vec![0u8; data_len];
                cursor
                    .read_exact(&mut block_state_data)
                    .map_err(|e| format!("Failed to read block state data: {}", e))?;

                let mut block_state_cursor = Cursor::new(block_state_data);
                let long_count = (4096 * bits_per_block as usize).div_ceil(64);
                for _ in 0..long_count {
                    section
                        .block_states
                        .block_states
                        .push(block_state_cursor.get_i64_le());
                }

                // Read biomes (3D array in 1.18+)
                for _ in 0..64 {
                    section.biomes.push(cursor.get_i32_le());
                }

                // Read lights
                cursor
                    .read_exact(&mut section.block_states.block_light)
                    .map_err(|e| format!("Failed to read block light: {}", e))?;
                cursor
                    .read_exact(&mut section.block_states.sky_light)
                    .map_err(|e| format!("Failed to read sky light: {}", e))?;

                sections.push(section);
            }
        }

        Ok(ChunkData::NewHeight(sections))
    }

    /// Convert chunk from one format to another
    fn convert_chunk(
        &self,
        chunk: ChunkData,
        from: ChunkFormat,
        to: ChunkFormat,
    ) -> Result<ChunkData, String> {
        match (from, to) {
            (ChunkFormat::Legacy, ChunkFormat::Flattened) => self.legacy_to_flattened(chunk),
            (ChunkFormat::Flattened, ChunkFormat::Legacy) => self.flattened_to_legacy(chunk),
            (ChunkFormat::Flattened, ChunkFormat::ModernBiomes) => {
                self.flattened_to_modern_biomes(chunk)
            },
            (ChunkFormat::ModernBiomes, ChunkFormat::Flattened) => {
                self.modern_biomes_to_flattened(chunk)
            },
            (ChunkFormat::ModernBiomes, ChunkFormat::NewHeight) => {
                self.modern_biomes_to_new_height(chunk)
            },
            (ChunkFormat::NewHeight, ChunkFormat::ModernBiomes) => {
                self.new_height_to_modern_biomes(chunk)
            },
            (ChunkFormat::Legacy, ChunkFormat::ModernBiomes) => {
                let flattened = self.legacy_to_flattened(chunk)?;
                self.flattened_to_modern_biomes(flattened)
            },
            (ChunkFormat::ModernBiomes, ChunkFormat::Legacy) => {
                let flattened = self.modern_biomes_to_flattened(chunk)?;
                self.flattened_to_legacy(flattened)
            },
            _ => Err(format!("Unsupported conversion: {:?} → {:?}", from, to)),
        }
    }

    /// Convert legacy to flattened
    fn legacy_to_flattened(&self, chunk: ChunkData) -> Result<ChunkData, String> {
        match chunk {
            ChunkData::Legacy(sections) => {
                let mut flattened_sections = Vec::new();

                for section in sections {
                    let mut flattened = FlattenedChunkSection::new();
                    let mut palette = std::collections::HashSet::new();

                    for i in 0..4096 {
                        let block_id = section.blocks[i] as u16;
                        let metadata = (section.metadata[i / 2] >> ((i % 2) * 4)) & 0x0F;
                        let combined_id = (block_id << 4) | metadata as u16;

                        let flattened_name = self.block_converter.to_flattened(combined_id);
                        palette.insert(flattened_name);
                    }

                    flattened.palette = palette.into_iter().collect();
                    let bits_per_block = Self::bits_per_block_for_palette(flattened.palette.len());
                    let entries_per_long = 64 / bits_per_block;
                    let long_count = (4096 * bits_per_block).div_ceil(64);
                    flattened.block_states = vec![0i64; long_count];

                    let palette_vec: Vec<_> = flattened.palette.to_vec();
                    for i in 0..4096 {
                        let block_id = section.blocks[i] as u16;
                        let metadata = (section.metadata[i / 2] >> ((i % 2) * 4)) & 0x0F;
                        let combined_id = (block_id << 4) | metadata as u16;

                        let flattened_name = self.block_converter.to_flattened(combined_id);
                        let index = palette_vec
                            .iter()
                            .position(|x| x == &flattened_name)
                            .unwrap_or(0);

                        let long_idx = i / entries_per_long;
                        let offset = (i % entries_per_long) * bits_per_block;
                        let mask = (1i64 << bits_per_block) - 1;
                        flattened.block_states[long_idx] |= (index as i64 & mask) << offset;
                    }

                    flattened.block_light = section.block_light.clone();
                    flattened.sky_light = section.sky_light.clone();

                    flattened_sections.push(flattened);
                }

                Ok(ChunkData::Flattened(flattened_sections))
            },
            _ => Err("Expected legacy chunk".into()),
        }
    }

    /// Convert flattened to legacy
    fn flattened_to_legacy(&self, chunk: ChunkData) -> Result<ChunkData, String> {
        match chunk {
            ChunkData::Flattened(sections) => {
                let mut legacy_sections = Vec::new();

                for section in sections {
                    let mut legacy = LegacyChunkSection::new();
                    let bits_per_block = Self::bits_per_block_for_palette(section.palette.len());
                    let entries_per_long = 64 / bits_per_block;
                    let mask = (1i64 << bits_per_block) - 1;

                    for i in 0..4096 {
                        let long_idx = i / entries_per_long;
                        let offset = (i % entries_per_long) * bits_per_block;
                        let palette_index = (section.block_states[long_idx] >> offset) & mask;
                        let flattened_name = section
                            .palette
                            .get(palette_index as usize)
                            .cloned()
                            .unwrap_or_else(|| "minecraft:air".to_string());

                        let legacy_id = self.block_converter.to_legacy(&flattened_name);
                        legacy.blocks[i] = (legacy_id >> 4) as u8;

                        let metadata = (legacy_id & 0x0F) as u8;
                        if i % 2 == 0 {
                            legacy.metadata[i / 2] = metadata;
                        } else {
                            legacy.metadata[i / 2] |= metadata << 4;
                        }
                    }

                    legacy.block_light = section.block_light.clone();
                    legacy.sky_light = section.sky_light.clone();

                    legacy_sections.push(legacy);
                }

                Ok(ChunkData::Legacy(legacy_sections))
            },
            _ => Err("Expected flattened chunk".into()),
        }
    }

    /// Convert flattened to modern biomes
    fn flattened_to_modern_biomes(&self, chunk: ChunkData) -> Result<ChunkData, String> {
        match chunk {
            ChunkData::Flattened(sections) => {
                let mut modern_sections = Vec::new();

                for section in sections {
                    let modern = ModernBiomeChunkSection {
                        block_states: section,
                        biomes: vec![0; 256], // Default to ocean
                    };
                    modern_sections.push(modern);
                }

                Ok(ChunkData::ModernBiomes(modern_sections))
            },
            _ => Err("Expected flattened chunk".into()),
        }
    }

    /// Convert modern biomes to flattened
    fn modern_biomes_to_flattened(&self, chunk: ChunkData) -> Result<ChunkData, String> {
        match chunk {
            ChunkData::ModernBiomes(sections) => {
                let mut flattened_sections = Vec::new();

                for section in sections {
                    flattened_sections.push(section.block_states);
                }

                Ok(ChunkData::Flattened(flattened_sections))
            },
            _ => Err("Expected modern biome chunk".into()),
        }
    }

    /// Convert modern biomes to new height
    fn modern_biomes_to_new_height(&self, chunk: ChunkData) -> Result<ChunkData, String> {
        match chunk {
            ChunkData::ModernBiomes(sections) => {
                let mut new_height_sections = Vec::new();

                for section in sections {
                    let new_height = NewHeightChunkSection {
                        block_states: section.block_states,
                        biomes: section.biomes.chunks(4).map(|chunk| chunk[0]).collect(), // Downsample 256 to 64
                    };
                    new_height_sections.push(new_height);
                }

                Ok(ChunkData::NewHeight(new_height_sections))
            },
            _ => Err("Expected modern biome chunk".into()),
        }
    }

    /// Convert new height to modern biomes
    fn new_height_to_modern_biomes(&self, chunk: ChunkData) -> Result<ChunkData, String> {
        match chunk {
            ChunkData::NewHeight(sections) => {
                let mut modern_sections = Vec::new();

                for section in sections {
                    let mut biomes = vec![0; 256];
                    for (i, &biome) in section.biomes.iter().enumerate() {
                        // Upsample 64 to 256
                        for j in 0..4 {
                            biomes[i * 4 + j] = biome;
                        }
                    }

                    let modern = ModernBiomeChunkSection {
                        block_states: section.block_states,
                        biomes,
                    };
                    modern_sections.push(modern);
                }

                Ok(ChunkData::ModernBiomes(modern_sections))
            },
            _ => Err("Expected new height chunk".into()),
        }
    }

    /// Encode chunk data based on format
    fn encode_chunk(&self, chunk: &ChunkData, format: ChunkFormat) -> Result<Vec<u8>, String> {
        let mut buf = BytesMut::new();

        match format {
            ChunkFormat::Legacy => self.encode_legacy_chunk(chunk, &mut buf)?,
            ChunkFormat::Flattened => self.encode_flattened_chunk(chunk, &mut buf)?,
            ChunkFormat::ModernBiomes => self.encode_modern_biome_chunk(chunk, &mut buf)?,
            ChunkFormat::NewHeight => self.encode_new_height_chunk(chunk, &mut buf)?,
        }

        Ok(buf.to_vec())
    }

    /// Encode legacy chunk
    fn encode_legacy_chunk(&self, chunk: &ChunkData, buf: &mut BytesMut) -> Result<(), String> {
        match chunk {
            ChunkData::Legacy(sections) => {
                let mut bitmask = 0u16;
                for (i, _section) in sections.iter().enumerate() {
                    bitmask |= 1 << i;
                }
                buf.put_u16_le(bitmask);

                for section in sections {
                    buf.put_slice(&section.blocks);
                    buf.put_slice(&section.metadata);
                    buf.put_slice(&section.block_light);
                    buf.put_slice(&section.sky_light);
                }

                Ok(())
            },
            _ => Err("Expected legacy chunk".into()),
        }
    }

    /// Encode flattened chunk
    fn encode_flattened_chunk(&self, chunk: &ChunkData, buf: &mut BytesMut) -> Result<(), String> {
        match chunk {
            ChunkData::Flattened(sections) => {
                let mut bitmask = 0u16;
                for (i, _) in sections.iter().enumerate() {
                    bitmask |= 1 << i;
                }
                buf.put_u16_le(bitmask);

                for section in sections {
                    let bits_per_block = Self::bits_per_block_for_palette(section.palette.len());
                    buf.put_u8(bits_per_block as u8);
                    buf.put_u16_le(section.palette.len() as u16);

                    for name in &section.palette {
                        buf.put_u16_le(name.len() as u16);
                        buf.put_slice(name.as_bytes());
                    }

                    buf.put_u32_le((section.block_states.len() * 8) as u32);
                    for &state in &section.block_states {
                        buf.put_i64_le(state);
                    }

                    buf.put_slice(&section.block_light);
                    buf.put_slice(&section.sky_light);
                }

                Ok(())
            },
            _ => Err("Expected flattened chunk".into()),
        }
    }

    /// Encode modern biome chunk
    fn encode_modern_biome_chunk(
        &self,
        chunk: &ChunkData,
        buf: &mut BytesMut,
    ) -> Result<(), String> {
        // Modern biome chunks use the same encoding as flattened
        self.encode_flattened_chunk(chunk, buf)
    }

    /// Encode new height chunk
    fn encode_new_height_chunk(&self, chunk: &ChunkData, buf: &mut BytesMut) -> Result<(), String> {
        match chunk {
            ChunkData::NewHeight(sections) => {
                let mut bitmask = 0i32;
                for (i, _) in sections.iter().enumerate() {
                    bitmask |= 1 << i;
                }
                buf.put_i32_le(bitmask);

                for section in sections {
                    let bits_per_block =
                        Self::bits_per_block_for_palette(section.block_states.palette.len());
                    buf.put_u8(bits_per_block as u8);
                    buf.put_u16_le(section.block_states.palette.len() as u16);

                    for name in &section.block_states.palette {
                        buf.put_u16_le(name.len() as u16);
                        buf.put_slice(name.as_bytes());
                    }

                    buf.put_u32_le((section.block_states.block_states.len() * 8) as u32);
                    for &state in &section.block_states.block_states {
                        buf.put_i64_le(state);
                    }

                    // Encode biomes
                    for &biome in &section.biomes {
                        buf.put_i32_le(biome);
                    }

                    buf.put_slice(&section.block_states.block_light);
                    buf.put_slice(&section.block_states.sky_light);
                }

                Ok(())
            },
            _ => Err("Expected new height chunk".into()),
        }
    }
}

impl Default for ChunkRepacker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_format_detection() {
        assert_eq!(
            chunk_format_for_version(ProtocolVersion::V1_12_2),
            ChunkFormat::Legacy
        );
        assert_eq!(
            chunk_format_for_version(ProtocolVersion::V1_13_2),
            ChunkFormat::Flattened
        );
        assert_eq!(
            chunk_format_for_version(ProtocolVersion::V1_16_5),
            ChunkFormat::ModernBiomes
        );
    }

    #[test]
    fn needs_repack() {
        assert!(ChunkRepacker::needs_repack(
            ProtocolVersion::V1_12_2,
            ProtocolVersion::V1_13_2
        ));
        assert!(!ChunkRepacker::needs_repack(
            ProtocolVersion::V1_12_2,
            ProtocolVersion::V1_12_2
        ));
    }
}
