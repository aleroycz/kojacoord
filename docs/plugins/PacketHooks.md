# Packet Hooks in Kojacoord Plugins

Packet hooks allow plugins to intercept, modify, or drop packets flowing through the proxy. This enables advanced customization and filtering capabilities.

## Overview

The packet hooking system provides:
- **Filtering**: Hook specific packets by protocol version and packet ID
- **Modification**: Change packet data before forwarding
- **Dropping**: Prevent packets from being sent
- **Replacement**: Replace packets with entirely different ones

## Basic Usage

### Registering Packet Hooks

Implement the `register_packet_hooks` method in your plugin:

```rust
use kojacoord_plugin_system::{
    Plugin, PluginContext, PacketEvent, PacketData, PacketHookResult, PacketDirection,
};
use bytes::Bytes;

struct MyPlugin {
    // Your plugin state
}

impl Plugin for MyPlugin {
    fn name(&self) -> &str { "my_plugin" }
    fn version(&self) -> &str { "1.0.0" }
    fn author(&self) -> &str { "Your Name" }
    fn description(&self) -> &str { "A plugin with packet hooks" }
    
    fn on_load(&mut self, _context: &PluginContext) -> anyhow::Result<()> {
        Ok(())
    }
    
    fn on_unload(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    
    fn on_enable(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    
    fn on_disable(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    
    fn handle_event(&mut self, _event: &PluginEvent) -> anyhow::Result<Option<PluginResponse>> {
        Ok(None)
    }
    
    fn register_packet_hooks(&mut self) -> Vec<PacketEvent> {
        vec![
            // Hook to specific clientbound packet
            PacketEvent::hook_to_clientbound(
                Some(340),  // Protocol version (1.12.2)
                Some(0x0E), // Packet ID (Chat message)
                |packet: &PacketData| {
                    // Your hook logic here
                    Ok(PacketHookResult::Forward)
                }
            ),
            
            // Hook to all serverbound packets for a protocol
            PacketEvent::hook_to_serverbound(
                Some(340),
                None,  // Any packet ID
                |packet: &PacketData| {
                    // Your hook logic here
                    Ok(PacketHookResult::Forward)
                }
            ),
        ]
    }
}
```

## Hook Types

### Forward Packet

Allow the packet to pass through unchanged:

```rust
PacketEvent::hook_to_clientbound(
    Some(340),
    Some(0x0E),
    |_packet| Ok(PacketHookResult::Forward)
)
```

### Drop Packet

Prevent the packet from being sent:

```rust
PacketEvent::hook_to_clientbound(
    Some(340),
    Some(0x0E),
    |packet| {
        if should_block_chat(packet) {
            Ok(PacketHookResult::Drop)
        } else {
            Ok(PacketHookResult::Forward)
        }
    }
)
```

### Modify Packet Data

Change the packet's byte data:

```rust
PacketEvent::hook_to_clientbound(
    Some(340),
    Some(0x0E),
    |packet| {
        let mut data = packet.data.to_vec();
        // Modify the chat message in the packet
        if let Some(pos) = data.windows(b"blocked".len())
            .position(|w| w == b"blocked") {
            data[pos..pos + 7].copy_from_slice(b"filtered");
        }
        Ok(PacketHookResult::Modify(Bytes::from(data)))
    }
)
```

### Replace Packet

Replace with a completely different packet:

```rust
PacketEvent::hook_to_clientbound(
    Some(340),
    Some(0x0E),
    |_packet| {
        // Create a different packet
        let new_data = Bytes::from(vec![/* packet bytes */]);
        Ok(PacketHookResult::Replace {
            packet_id: 0x01,  // Different packet ID
            data: new_data,
        })
    }
)
```

## Advanced Examples

### Chat Filter Plugin

```rust
fn register_packet_hooks(&mut self) -> Vec<PacketEvent> {
    vec![
        PacketEvent::hook_to_clientbound(
            Some(340),  // 1.12.2
            Some(0x0E), // Chat message
            |packet| {
                let message = String::from_utf8_lossy(&packet.data);
                if message.contains("badword") {
                    Ok(PacketHookResult::Drop)
                } else {
                    Ok(PacketHookResult::Forward)
                }
            }
        ),
    ]
}
```

### Packet Logger Plugin

```rust
fn register_packet_hooks(&mut self) -> Vec<PacketEvent> {
    vec![
        PacketEvent::hook_to_serverbound(
            None, // All protocols
            None, // All packets
            |packet| {
                log::info!("Packet: dir={:?} id=0x{:02X} len={}",
                    packet.direction,
                    packet.packet_id,
                    packet.data.len()
                );
                Ok(PacketHookResult::Forward)
            }
        ),
    ]
}
```

### Protocol-Specific Hook

```rust
fn register_packet_hooks(&mut self) -> Vec<PacketEvent> {
    vec![
        // Only hook 1.8 packets
        PacketEvent::hook_to_clientbound(
            Some(47),  // 1.8 protocol
            None,
            |packet| {
                // Handle 1.8 specific logic
                Ok(PacketHookResult::Forward)
            }
        ),
        
        // Only hook 1.12.2 packets
        PacketEvent::hook_to_clientbound(
            Some(340),  // 1.12.2 protocol
            None,
            |packet| {
                // Handle 1.12.2 specific logic
                Ok(PacketHookResult::Forward)
            }
        ),
    ]
}
```

## Packet Data Structure

```rust
pub struct PacketData {
    pub protocol_version: u32,  // Minecraft protocol version
    pub packet_id: i32,         // Packet ID
    pub direction: PacketDirection,  // Clientbound or Serverbound
    pub data: Bytes,            // Raw packet bytes
    pub player_uuid: Option<Uuid>,  // Associated player if available
}
```

## Hook Result Types

```rust
pub enum PacketHookResult {
    /// Forward the packet as-is
    Forward,
    /// Drop the packet (don't send it)
    Drop,
    /// Modify the packet data
    Modify(Bytes),
    /// Replace with a different packet
    Replace { packet_id: i32, data: Bytes },
}
```

## Common Protocol Versions

- 47: Minecraft 1.8
- 107: Minecraft 1.9
- 210: Minecraft 1.10
- 315: Minecraft 1.11
- 340: Minecraft 1.12.2
- 404: Minecraft 1.13.2
- 477: Minecraft 1.14.4
- 498: Minecraft 1.15.2
- 573: Minecraft 1.16.5
- 754: Minecraft 1.17.1
- 755: Minecraft 1.18
- 759: Minecraft 1.18.2
- 761: Minecraft 1.19
- 762: Minecraft 1.19.1
- 763: Minecraft 1.19.3

## Performance Considerations

- Packet hooks are called for every matching packet
- Keep hook logic minimal to avoid latency
- Use specific filters (protocol version + packet ID) when possible
- Avoid heavy computations in hot paths
- Consider using caching for expensive operations

## Security Notes

- Always validate packet modifications
- Be careful with packet replacement to avoid protocol violations
- Malformed packets can cause client disconnects
- Test thoroughly across different protocol versions

## Building Plugin Libraries

To build a plugin as a dynamic library:

```toml
# Cargo.toml
[lib]
crate-type = ["cdylib"]

[dependencies]
kojacoord-plugin-system = { path = "../path/to/plugin-system" }
```

```rust
// lib.rs
use kojacoord_plugin_system::*;

struct MyPlugin;

impl Plugin for MyPlugin {
    // Implementation
}

#[no_mangle]
pub extern "C" fn get_metadata() -> PluginMetadata {
    PluginMetadata {
        name: "my_plugin".to_string(),
        version: "1.0.0".to_string(),
        author: "Your Name".to_string(),
        description: "Description".to_string(),
        min_proxy_version: "0.1.0".to_string(),
        dependencies: vec![],
    }
}

#[no_mangle]
pub extern "C" fn create_plugin() -> *mut dyn Plugin {
    Box::into_raw(Box::new(MyPlugin))
}
```
