import json, struct, sys

TAGID = {'end':0,'byte':1,'short':2,'int':3,'long':4,'float':5,'double':6,
         'byteArray':7,'string':8,'list':9,'compound':10,'intArray':11,'longArray':12}

def w_varint(out, v):
    """
    Encode an integer as a 32-bit masked varint and append its bytes to the given output.
    
    Parameters:
        out (bytearray | list): Mutable byte container to which the varint-encoded bytes will be appended.
        v (int): Integer value to encode; masked to 32 bits before encoding.
    """
    v &= 0xFFFFFFFF
    while True:
        b = v & 0x7F
        v >>= 7
        if v: out.append(b | 0x80)
        else: out.append(b); break

def w_mc_string(out, s):
    """
    Encode a Python string as UTF-8 with a Minecraft-style varint length prefix and append the bytes to `out`.
    
    Parameters:
        out (bytearray or list): Mutable byte buffer to which the length prefix and UTF-8 bytes will be appended.
        s (str): The string to encode.
    """
    b = s.encode('utf-8'); w_varint(out, len(b)); out += b

def long_i64(v):
    """
    Normalize a "long" input into a 64-bit integer suitable for packing.
    
    Parameters:
        v (int | list): Either an integer already representing the 64-bit value, or a two-element list [high, low] where `high` is the high 32 bits and `low` is the low 32 bits.
    
    Returns:
        int: The resulting 64-bit integer. If `v` is a two-element list, returns (high << 32) | (low & 0xFFFFFFFF); otherwise returns `v` unchanged.
    """
    if isinstance(v, list): return (v[0] << 32) | (v[1] & 0xFFFFFFFF)
    return v

def w_payload(out, ttype, val):
    """
    Serialize an NBT payload (unnamed) for the given tag type into the provided bytearray.
    
    Parameters:
        out (bytearray or list): Mutable byte buffer to append the encoded payload bytes.
        ttype (str): NBT tag type name (one of: 'byte', 'short', 'int', 'long', 'float', 'double',
            'string', 'byteArray', 'intArray', 'longArray', 'list', 'compound').
        val: Value to serialize for the given tag type. Expected shapes:
            - Primitives ('byte','short','int','long','float','double'): numeric value.
            - 'string': Python str (UTF-8 encoded with 16-bit big-endian length prefix).
            - 'byteArray' / 'intArray' / 'longArray': iterable of numbers (arrays are length-prefixed with 32-bit big-endian count).
            - 'long' and 'longArray' elements may be integers or 2-element [high, low] lists (normalized by long_i64).
            - 'list': dict with keys 'type' (element tag name) and 'value' (iterable of element values).
            - 'compound': dict mapping string keys to tag descriptors of the form {'type': <tag>, 'value': <val>}.
    
    Raises:
        SystemExit: if `ttype` is not a recognized NBT tag type.
    """
    if ttype=='byte': out += struct.pack('>b', val)
    elif ttype=='short': out += struct.pack('>h', val)
    elif ttype=='int': out += struct.pack('>i', val)
    elif ttype=='long': out += struct.pack('>q', long_i64(val))
    elif ttype=='float': out += struct.pack('>f', val)
    elif ttype=='double': out += struct.pack('>d', val)
    elif ttype=='string':
        b=val.encode('utf-8'); out += struct.pack('>H', len(b)); out += b
    elif ttype=='byteArray':
        out += struct.pack('>i', len(val))
        for x in val: out += struct.pack('>b', x)
    elif ttype=='intArray':
        out += struct.pack('>i', len(val))
        for x in val: out += struct.pack('>i', x)
    elif ttype=='longArray':
        out += struct.pack('>i', len(val))
        for x in val: out += struct.pack('>q', long_i64(x))
    elif ttype=='list':
        et=val['type']; items=val['value']
        out += struct.pack('>B', TAGID[et]); out += struct.pack('>i', len(items))
        for it in items: w_payload(out, et, it)
    elif ttype=='compound':
        for k,tv in val.items():
            out += struct.pack('>B', TAGID[tv['type']])
            kb=k.encode('utf-8'); out += struct.pack('>H', len(kb)); out += kb
            w_payload(out, tv['type'], tv['value'])
        out += b'\x00'
    else: raise SystemExit('bad type '+ttype)

def w_nameless(out, tag):
    # network NBT (1.20.2+): tag_id byte + payload, NO name
    """
    Append a nameless NBT tag (type ID byte followed by payload) to a mutable byte buffer.
    
    Parameters:
        out (bytearray or list): Mutable buffer to which the tag bytes are appended.
        tag (dict): Tag object with keys:
            - 'type' (str): NBT tag type name (must be a key in TAGID).
            - 'value': The tag payload to be serialized according to its type.
    """
    out += struct.pack('>B', TAGID[tag['type']])
    w_payload(out, tag['type'], tag['value'])

codec = json.load(open(sys.argv[1]))['dimensionCodec']
packets = []  # each = RegistryData body for one registry
for reg_id, reg in codec.items():
    body = bytearray()
    w_mc_string(body, reg_id)
    entries = reg['entries']
    w_varint(body, len(entries))
    for e in entries:
        w_mc_string(body, e['key'])
        v = e.get('value')
        if v is None:
            body.append(0)  # has_data = false
        else:
            body.append(1)  # has_data = true
            w_nameless(body, v)
    packets.append(bytes(body))

# bundle: [u32 num][ u32 len, bytes ]*
bundle = bytearray()
bundle += struct.pack('>I', len(packets))
for p in packets:
    bundle += struct.pack('>I', len(p)); bundle += p
open(sys.argv[2],'wb').write(bundle)
print('wrote', sys.argv[2], len(bundle), 'bytes,', len(packets), 'registries:', [r for r in codec])
