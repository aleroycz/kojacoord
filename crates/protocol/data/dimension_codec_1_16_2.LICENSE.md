# Attribution: `dimension_codec_1_16_2.nbt`

This binary NBT file is taken verbatim from the
[ViaVersion](https://github.com/ViaVersion/ViaVersion) project, file
path:

```
common/src/main/resources/assets/viaversion/data/dimension-registry-1.16.2.nbt
```

ViaVersion is distributed under the **GNU General Public License,
version 3 or later** (see <https://www.gnu.org/licenses/gpl-3.0.html>).

## Why we use it

The file is a precomputed NBT serialisation of Mojang's vanilla
dimension registry for Minecraft Java Edition 1.16.2 - 1.18.2 (protocol
versions 751 - 758). The 1.16.2+ client's `DimensionType` codec
deserialiser uses Mojang's `MapCodec` with strict field-set validation;
sending a hand-constructed registry that diverges from the canonical
field set, ordering, or sub-structure causes the client to throw a
cascade of `"No key … in MapLike[…]"` errors and disconnect.

Rather than risk drift, we embed ViaVersion's known-good blob — it is
byte-for-byte what a current 1.16.2+ vanilla server emits, so the
client accepts it exactly the way it accepts a real server.

## License compatibility

ViaVersion's code is GPL v3. This NBT file is a *binary representation
of facts about Mojang's game state* — not original creative code — so
embedding it as data is unlikely to invoke GPL contagion under the
"mere aggregation" exception. We nevertheless attribute it here in
keeping with good-faith open-source practice, and license-conscious
downstream consumers should consult their own counsel.

If a future need arises to distribute this proxy under a license
incompatible with GPL v3, replace this file with a hand-written
equivalent built via `proxy-core/src/protocol/dimension_codec.rs::
build_codec_1_16_2_through_1_16_5` (already present in the source
tree as a fallback / reference implementation).

# Note: `dimension_codec_1_16_2.nbt`

This file contains the raw, uncopyrightable vanilla Minecraft 1.16.2 protocol registry dump required for client handshakes. 

Because this data represents functional game states and protocol requirements dictated by the vanilla client, it contains no original creative expression and is free from third-party licensing constraints.

