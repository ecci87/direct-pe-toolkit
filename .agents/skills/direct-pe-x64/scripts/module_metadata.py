"""Concise embedded descriptions; optional compressed edit records, no opcode selection."""
import copy
import hashlib
import json
import struct
import zlib

FLAG = 1
MAGIC = b"LLMFX64\0"
HEADER = 48
LIMIT = 16*1024*1024

def compact(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("utf-8")

def parts(document,kind):
    """Keep semantics readable. Keep only mechanical edit information in the tail."""
    d=copy.deepcopy(document)
    brief={k:d[k] for k in ("schema","name","contract_version","purpose") if k in d}
    technical={}
    if kind==1:
        abi=d.get("abi",{})
        brief["abi"]={k:abi[k] for k in ("inputs","returns","memory_contracts") if k in abi}
        brief["abi"]["platform"]="Windows x64"
        brief["profile"]=d["implementation"]["unwind_profile"]
        refs=d.get("references",[])
        brief["calls"]=sorted({r["target"] for r in refs if r["kind"]=="call" and r.get("local") is None})
        brief["imports"]=sorted({r["target"].removeprefix("iat.") for r in refs if r["kind"]=="import"})
        if d.get("tests"):brief["tests"]=d["tests"]
        technical={k:d[k] for k in ("abi","implementation","references","local_symbols") if k in d}
    elif kind==4:
        technical["symbols"]=d.get("symbols",{})
        brief["symbol_count"]=len(technical["symbols"])
    elif kind==3:
        for k in ("commands","native_modes","validation"):
            if k in d:brief[k]=d[k]
        design=d.get("design",{})
        brief["design"]={"model":"Named function slots, bounded data contracts and Windows DLL imports."}
        for k in ("data","entrypoints","system_imports"):
            if k in design:brief["design"][k]=design[k]
        if "reserve_profile" in d:brief["reserve_profile"]=d["reserve_profile"]
    else:
        # Contract fields/units/bounds/ownership are semantics: never silently truncate them.
        brief.update({k:v for k,v in d.items() if k not in ("notes","change","schema","name","contract_version","purpose")})
    return brief,technical

def encode(document,kind):
    brief,technical=parts(document,kind)
    payload=compact(brief)
    extra=b""
    if technical:
        decoded=compact(technical)
        packed=zlib.compress(decoded,9)
        extra=MAGIC+struct.pack("<II",len(packed),len(decoded))+hashlib.sha256(packed).digest()+packed
    return payload,extra

def stored_size(document,kind):
    payload,extra=encode(document,kind)
    return len(payload)+1+len(extra)

def pack(document,record):
    payload,extra=encode(document,record["kind"])
    capacity=record["doc_capacity"]
    extra_at=capacity-len(extra)
    if len(payload)+1>extra_at:
        raise ValueError("Module metadata slot exhausted: "+record["name"])
    result=dict(record,flags=record.get("flags",0)|FLAG,
        doc_size=len(payload),doc_hash=hashlib.sha256(payload).digest(),
        technical_rva=record["doc_rva"]+extra_at if extra else 0)
    return result,payload+b"\0"*(extra_at-len(payload))+extra

def decode(header,payload):
    if len(header)!=HEADER or header[:8]!=MAGIC:
        raise ValueError("Invalid technical-record header")
    packed_size,decoded_size=struct.unpack_from("<II",header,8)
    if packed_size!=len(payload) or decoded_size>LIMIT or hashlib.sha256(payload).digest()!=header[16:48]:
        raise ValueError("Technical-record length/hash mismatch")
    decoder=zlib.decompressobj()
    decoded=decoder.decompress(payload,LIMIT+1)
    if len(decoded)!=decoded_size or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("Technical-record decompression bounds mismatch")
    return json.loads(decoded)

def expand(brief,technical):
    document=copy.deepcopy(brief)
    if "implementation" in technical:
        document.pop("profile",None);document.pop("calls",None);document.pop("imports",None)
    if "symbols" in technical:document.pop("symbol_count",None)
    document.update(technical)
    if "implementation" in document:
        refs=document.get("references",[])
        document["dependencies"]=dict(
            functions=sorted({r["target"] for r in refs if r["kind"]=="call"}),
            imports=sorted({r["target"].removeprefix("iat.") for r in refs if r["kind"]=="import"}),
            memory_symbols=sorted({r["target"] for r in refs if r["kind"]=="rip"}),
            contracts=document.get("abi",{}).get("memory_contracts",[]))
    return document
