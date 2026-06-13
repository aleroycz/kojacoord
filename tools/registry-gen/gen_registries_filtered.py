import json, struct, sys

TAGID = {'end':0,'byte':1,'short':2,'int':3,'long':4,'float':5,'double':6,
         'byteArray':7,'string':8,'list':9,'compound':10,'intArray':11,'longArray':12}
def w_varint(out, v):
    """
    Encode an integer as a 32-bit masked varint and append its resulting bytes to a byte-list buffer.
    
    Writes the value masked to 32 bits as one or more 7-bit little-endian chunks with the high continuation bit set on every byte except the final one.
    
    Parameters:
        out (list or bytearray): A mutable sequence to which encoded byte values (0–255) will be appended.
        v (int): The integer to encode; it will be masked to 32 bits before encoding.
    """
    v &= 0xFFFFFFFF
    while True:
        b = v & 0x7F; v >>= 7
        if v: out.append(b|0x80)
        else: out.append(b); break
def w_mcstr(out, s):
    """
    Encode a Python string as a Minecraft-style UTF-8 string and append it to the output buffer.
    
    Parameters:
        out (bytearray or list-like): Buffer to which the varint length and UTF-8 bytes will be appended using +=.
        s (str): String to encode.
    
    Returns:
        None
    """
    b=s.encode(); w_varint(out,len(b)); out+=b
def long_i64(v): """
Convert a two-element [hi, lo] list into a single 64-bit integer, or return the input unchanged.

Parameters:
    v (int | list): Either an integer value or a two-element list [hi, lo] where `hi` is the high 32 bits and `lo` is the low 32 bits.

Returns:
    int | Any: If `v` is a list, an integer composed as (hi << 32) | (lo & 0xFFFFFFFF). Otherwise, returns `v` unchanged.
"""
return (v[0]<<32)|(v[1]&0xFFFFFFFF) if isinstance(v,list) else v
def w_payload(out,t,val):
    """
    Serialize a typed value into the given byte buffer according to the module's NBT-like binary format.
    
    Parameters:
        out (bytearray or list): Mutable byte buffer to which the serialized bytes are appended.
        t (str): Tag type name; one of 'byte', 'short', 'int', 'long', 'float', 'double',
            'string', 'byteArray', 'intArray', 'longArray', 'list', or 'compound'.
        val: Value to serialize. Expected shapes by type:
            - 'byte', 'short', 'int', 'float', 'double': a numeric value.
            - 'long': an int or a two-element list [hi, lo] representing a 64-bit value.
            - 'string': a Python str (UTF-8 encoded).
            - 'byteArray' / 'intArray' / 'longArray': an iterable of element values
              (for 'longArray', elements may be int or [hi, lo]).
            - 'list': a dict {'type': element_type_name, 'value': [items...]}.
            - 'compound': a mapping of key -> {'type': type_name, 'value': value}.
    
    Behavior:
        Appends the binary representation of `val` for the given type `t` to `out`.
        Numeric values are written big-endian. Strings are written as a big-endian
        unsigned 16-bit length followed by UTF-8 bytes. Arrays and lists include
        their lengths as 32-bit signed integers. Compounds write each entry as
        (type id byte, name length + name bytes, payload) and are terminated with
        a single zero byte.
    """
    if t=='byte': out+=struct.pack('>b',val)
    elif t=='short': out+=struct.pack('>h',val)
    elif t=='int': out+=struct.pack('>i',val)
    elif t=='long': out+=struct.pack('>q',long_i64(val))
    elif t=='float': out+=struct.pack('>f',val)
    elif t=='double': out+=struct.pack('>d',val)
    elif t=='string':
        b=val.encode(); out+=struct.pack('>H',len(b)); out+=b
    elif t=='byteArray':
        out+=struct.pack('>i',len(val))
        for x in val: out+=struct.pack('>b',x)
    elif t=='intArray':
        out+=struct.pack('>i',len(val))
        for x in val: out+=struct.pack('>i',x)
    elif t=='longArray':
        out+=struct.pack('>i',len(val))
        for x in val: out+=struct.pack('>q',long_i64(x))
    elif t=='list':
        et=val['type']; items=val['value']
        out+=struct.pack('>B',TAGID[et]); out+=struct.pack('>i',len(items))
        for it in items: w_payload(out,et,it)
    elif t=='compound':
        for k,tv in val.items():
            out+=struct.pack('>B',TAGID[tv['type']])
            kb=k.encode(); out+=struct.pack('>H',len(kb)); out+=kb
            w_payload(out,tv['type'],tv['value'])
        out+=b'\x00'
def w_nameless(out,tag):
    """
    Write an unnamed/tag-without-name NBT-style tag into the given output buffer.
    
    Parameters:
        out (bytearray or list-like): Buffer to append raw bytes to; the function appends the tag type ID (1 byte) and the serialized payload.
        tag (dict): Mapping with keys 'type' (string tag name matching TAGID) and 'value' (payload to serialize for that type).
    """
    out+=struct.pack('>B',TAGID[tag['type']]); w_payload(out,tag['type'],tag['value'])

codec=json.load(open(sys.argv[1]))['dimensionCodec']
include=set(sys.argv[3].split(',')) if len(sys.argv)>3 and sys.argv[3] else None
packets=[]
for reg_id,reg in codec.items():
    if include is not None and reg_id not in include: continue
    body=bytearray(); w_mcstr(body,reg_id)
    entries=reg['entries']; w_varint(body,len(entries))
    for e in entries:
        w_mcstr(body,e['key']); v=e.get('value')
        if v is None: body.append(0)
        else: body.append(1); w_nameless(body,v)
    packets.append(bytes(body))
bundle=bytearray(); bundle+=struct.pack('>I',len(packets))
for p in packets: bundle+=struct.pack('>I',len(p)); bundle+=p
open(sys.argv[2],'wb').write(bundle)
print('wrote',sys.argv[2],len(bundle),'bytes,',len(packets),'registries')
