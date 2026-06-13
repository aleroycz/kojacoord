# Registry / dimension-codec generators

Convert PrismarineJS `minecraft-data` `pc/<ver>/loginPacket.json`
into the binary NBT / packet-bundle blobs embedded by
`crates/proxy-core/src/protocol/dimension_codec.rs` and
`crates/proxy-core/src/net/registry_data.rs`.

## conv_nbt.py — JoinGame dimension codec (1.16.2 … 1.20.1, proto ≤763)
Emits a big-endian, named-root NBT blob (the whole `dimensionCodec`).
```
python3 conv_nbt.py <minecraft-data>/data/pc/<ver>/loginPacket.json out.nbt
```
Used for: `dimension_codec_1_17.nbt`, `_1_18.nbt`, `_1_18_2.nbt`,
`_1_19.nbt`, `_1_19_2.nbt`, `_1_19_4.nbt`, `_1_20.nbt`.

## gen_registries.py — config-phase RegistryData bundle (1.20.5+, proto ≥766)
Splits the rich `dimensionCodec` (`{registry_id:{entries:[{key,value}]}}`)
into one `ClientboundRegistryData` body per registry, bundled as
`[u32 num][u32 len, body]*`. Each body is
`String(id) + VarInt(count) + [String(key)+bool+nameless-NBT]*`.
```
python3 gen_registries.py <minecraft-data>/data/pc/<ver>/loginPacket.json out.bin
```
Used for: `registries_1_20_5.bin` (766), `registries_1_21.bin` (767),
`registries_1_21_3.bin` (768/769).

## gen_registries_filtered.py — per-version subset of a complete codec
minecraft-data's `loginPacket` codec is a *sample*, not the authoritative
required set (e.g. its 1.21.9 dump lists only 11 registries, missing the
mob-variant ones 1.21.5 added). For versions with no exact rich codec,
filter the newest *complete* codec (`pc/1.21.11`, 23 registries) down to
the registry set that version actually requires — the set grows per
release, and ViaVersion's protocol transitions tell you what each added:
```
python3 gen_registries_filtered.py <…>/1.21.11/loginPacket.json out.bin "minecraft:a,minecraft:b,…"
```
Pass an empty filter (`""`) for the full set. Used for:
`registries_1_21_5.bin` (770: base-12 + cat/chicken/cow/frog/pig/
wolf_sound variants per `Protocol1_21_4To1_21_5`), `registries_1_21_6.bin`
(771-773: + `dialog` per `Protocol1_21_5To1_21_6`),
`registries_1_21_11.bin` (774: full 23).

Source of truth: minecraft.wiki + PrismarineJS/minecraft-data for the
codec *contents*; ViaVersion for the per-version required-registry *set*.
BungeeCord is same-version and carries no registry data to cross-check.
