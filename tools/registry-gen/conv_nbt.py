import json, struct, sys

def w_str(out, s):
    """
    Append a length-prefixed UTF-8 encoding of `s` to `out`.
    
    Parameters:
        out (bytearray): Bytearray to append the encoded data to; mutated in place.
        s (str): String to encode as UTF-8. The function writes a 2-byte big-endian unsigned length followed by the encoded bytes.
    """
    b = s.encode('utf-8'); out += struct.pack('>H', len(b)); out += b

TAGID = {'end':0,'byte':1,'short':2,'int':3,'long':4,'float':5,'double':6,
         'byteArray':7,'string':8,'list':9,'compound':10,'intArray':11,'longArray':12}

def long_to_i64(v):
    # prismarine-nbt longs are [high, low] int32 pairs
    """
    Convert a prismarine-nbt long represented as a [high, low] int32 pair into a single 64-bit integer.
    
    Parameters:
        v (int | list): Either an integer already representing a 64-bit value, or a two-element list [high, low] of 32-bit signed integers.
    
    Returns:
        int: The 64-bit integer assembled from the pair when `v` is a list; otherwise returns `v` unchanged.
    """
    if isinstance(v, list):
        return (v[0] << 32) | (v[1] & 0xFFFFFFFF)
    return v

def w_payload(out, ttype, val):
    """
    Serialize a value into NBT payload form and append the bytes to `out`.
    
    Parameters:
        out (bytearray): Destination bytearray to which serialized bytes are appended.
        ttype (str): NBT tag type name (e.g. 'byte', 'short', 'int', 'long', 'float', 'double',
                     'string', 'byteArray', 'intArray', 'longArray', 'list', 'compound').
        val: Value to serialize; its expected shape depends on `ttype`:
            - numeric primitives ('byte','short','int','long','float','double'): a Python number.
            - 'string': a Python str.
            - 'byteArray': a sequence of integers (each -128..127).
            - 'intArray': a sequence of integers.
            - 'longArray': a sequence of 64-bit values or prismarine-style [high, low] pairs.
            - 'list': a dict with keys 'type' (element type name) and 'value' (list of elements).
            - 'compound': a dict mapping names to dicts of the form {'type': <type_name>, 'value': <value>}.
    
    Raises:
        SystemExit: if `ttype` is not a recognized NBT type.
    """
    if ttype == 'byte':   out += struct.pack('>b', val)
    elif ttype=='short':  out += struct.pack('>h', val)
    elif ttype=='int':    out += struct.pack('>i', val)
    elif ttype=='long':   out += struct.pack('>q', long_to_i64(val))
    elif ttype=='float':  out += struct.pack('>f', val)
    elif ttype=='double': out += struct.pack('>d', val)
    elif ttype=='string': w_str(out, val)
    elif ttype=='byteArray':
        out += struct.pack('>i', len(val))
        for x in val: out += struct.pack('>b', x)
    elif ttype=='intArray':
        out += struct.pack('>i', len(val))
        for x in val: out += struct.pack('>i', x)
    elif ttype=='longArray':
        out += struct.pack('>i', len(val))
        for x in val: out += struct.pack('>q', long_to_i64(x))
    elif ttype=='list':
        et = val['type']; items = val['value']
        out += struct.pack('>B', TAGID[et])
        out += struct.pack('>i', len(items))
        for it in items:
            w_payload(out, et, it)
    elif ttype=='compound':
        # val is dict name->{type,value}
        for k, tv in val.items():
            out += struct.pack('>B', TAGID[tv['type']])
            w_str(out, k)
            w_payload(out, tv['type'], tv['value'])
        out += b'\x00'
    else:
        raise SystemExit('unknown type '+ttype)

d = json.load(open(sys.argv[1]))
codec = d['dimensionCodec']  # {type:'compound', name:'', value:{...}}
out = bytearray()
out += struct.pack('>B', TAGID['compound'])
w_str(out, codec.get('name',''))
w_payload(out, 'compound', codec['value'])
open(sys.argv[2],'wb').write(out)
print('wrote', sys.argv[2], len(out), 'bytes')
