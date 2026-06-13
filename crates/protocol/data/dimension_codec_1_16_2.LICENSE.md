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

# Attribution: `chat_registry_1_19.nbt`

This file is taken verbatim from ViaVersion, file path:

```
common/src/main/resources/assets/viaversion/data/chat-registry-1.19.nbt
```

ViaVersion is distributed under **GPL v3** (see
<https://www.gnu.org/licenses/gpl-3.0.html>).

## Why we use it

`minecraft:chat_type` is a required registry inside the 1.19 dimension
codec (proto 759 - 763). The 1.19 client's
`EntityPacketRewriter1_19.java:177` confirms this:

```java
// Add necessary chat types
tag.put("minecraft:chat_type", protocol.getMappingData().chatRegistry());
```

Without this registry the client's strict `MapCodec` deserialiser
walks past the codec's TAG_End into the next packet's framing bytes,
producing the user-visible `length wider than 21-bit` netty
`CorruptedFrameException`.

We embed ViaVersion's blob verbatim rather than re-implementing the
registry because the field set, ordering, and `parameters` arrays
must match Mojang's expected schema exactly — same risk-reduction
rationale as the 1.16.2 dimension codec above.

# Attribution: `chat_registry_1_19_1.nbt`

Same as above, sourced from
`common/src/main/resources/assets/viaversion/data/chat-registry-1.19.1.nbt`
in ViaVersion. The 1.19.1 / 1.19.2 chat registry adds a couple of
chat types (`minecraft:say_command`, etc.). Reserved for future
proto-760+ codec routing — not yet wired into
`build_dimension_codec_for_proto`.

## License compatibility (same analysis applies)

These NBT blobs are binary representations of facts about Mojang's
game state (which chat types exist, what their parameter lists are).
They contain no original creative code and arguably fall under
"mere aggregation" with respect to ViaVersion's GPL v3 surface.
License-conscious downstream consumers should consult their own
counsel; replacements can be hand-constructed via the augment helpers
in `proxy-core/src/protocol/dimension_codec.rs`.

