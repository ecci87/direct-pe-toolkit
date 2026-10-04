#!/usr/bin/env python3
"""Starfall combat migration: explicit x64 bytes, PE packing and declared fixups only."""
import argparse, copy, importlib.util, json, struct
from pathlib import Path

def load_workbench(path):
    spec=importlib.util.spec_from_file_location("wb",path)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod

class Bytes:
    def __init__(self,prefix):
        self.b=bytearray(); self.refs=[]; self.labels={}; self.prefix=prefix
    def e(self,h): self.b.extend(bytes.fromhex(h))
    def u(self,n): self.b.extend(struct.pack("<I",n&0xffffffff))
    def label(self,name): self.labels[self.prefix+"."+name]=len(self.b)
    def r(self,h,target,tail="",kind="rip"):
        self.e(h); off=len(self.b); self.u(0); self.e(tail)
        self.refs.append(dict(offset=off,next_offset=len(self.b),target=target,local=None,kind=kind,rva=0))
    def j(self,h,label): self.r(h,self.prefix+"."+label,kind="branch")
    def ready(self):
        for ref in self.refs:
            if ref["target"] in self.labels: ref["local"]=self.labels[ref["target"]]
        return self

def splice(module,start,end,fragment,preserve_label=False):
    fragment.ready(); old=bytes.fromhex(module["code_hex"]); delta=len(fragment.b)-(end-start)
    doc=module["document"]; refs=[]
    def shift_local(value):
        if start==end and preserve_label and value==start: return value
        if value>=end: return value+delta
        if start<=value<end: raise ValueError("Replacing a declared local target")
        return value
    for ref in doc["references"]:
        if start<=ref["offset"]<end: continue
        ref=copy.deepcopy(ref)
        if ref["offset"]>=end: ref["offset"]+=delta; ref["next_offset"]+=delta
        if ref["local"] is not None: ref["local"]=shift_local(ref["local"])
        refs.append(ref)
    for ref in fragment.refs:
        ref=copy.deepcopy(ref); ref["offset"]+=start; ref["next_offset"]+=start
        if ref["local"] is not None: ref["local"]+=start
        elif ref["target"] in doc["local_symbols"]: ref["local"]=shift_local(doc["local_symbols"][ref["target"]])
        refs.append(ref)
    doc["local_symbols"]={name:shift_local(value) for name,value in doc["local_symbols"].items()}
    doc["local_symbols"].update({name:start+value for name,value in fragment.labels.items()})
    doc["references"]=refs
    module["code_hex"]=(old[:start]+fragment.b+old[end:]).hex()
    doc["implementation"]["used_bytes"]=len(bytes.fromhex(module["code_hex"]))

def build(args):
    wb=load_workbench(args.workbench)
    source=Path(args.source).resolve(); out=Path(args.directory).resolve()
    arch=out/"architecture"; arch.mkdir(parents=True,exist_ok=True)
    spec=json.loads((source/"migration-v2.json").read_text(encoding="utf-8"))
    original=source/"Starfall-v1.exe"
    baseline_bytes=original.read_bytes()
    modules=spec["modules"]; by={m["name"]:m for m in modules}
    symbols=by["Symbols"]["document"]["symbols"]
    with wb.PE(original,metadata=False) as pe:
        headers=bytearray(pe.read(0,pe.headers_size))
        sections=copy.deepcopy(pe.sections)
        raw_sections={s["name"]:bytearray(pe.read(s["raw_offset"],s["raw_size"])) for s in sections}
        rdata=raw_sections[".rdata"]; cursor=len(rdata)
        rdata.extend(b"\0"*(0x4000-len(rdata)))
        for section in sections:
            if section["name"]==".rdata": section["raw_size"]=0x4000
        def ro_string(name,text):
            nonlocal cursor
            payload=(text+"\0").encode("ascii")
            if cursor+len(payload)>len(rdata): raise ValueError("Read-only reserve exhausted")
            symbols[name]=0x11000+cursor
            rdata[cursor:cursor+len(payload)]=payload; cursor+=len(payload)
        def replace_string(name,text):
            at=symbols[name]-0x11000; end=rdata.index(0,at); width=end-at
            if len(text)>width: raise ValueError("Existing string exceeds reserve")
            rdata[at:end]=text.ljust(width).encode("ascii")
        replace_string("welcome","     ENTER / SPACE: START     ")
        replace_string("welcome2"," Dodge the stars and meteors! ")
        replace_string("smoke2","400 frames written through WriteConsoleOutputA\r\n")
        template=symbols["template"]-0x11000
        for row,text in {
            22:"       ARROWS / WASD: MOVE    SPACE: FIRE (EVERY 5s)",
            23:"       ^ YOU   * SHOOTABLE   # INDESTRUCTIBLE   ESC: QUIT",
            24:"       ENTER: START    R / ENTER: RESTART",
        }.items():
            for x,char in enumerate(text.ljust(64)):
                struct.pack_into("<H",rdata,template+(row*64+x)*4,ord(char))
        symbols.update({"combat":0x18000,"combat.hazard":0x180e0,"combat.guard":0x18480})
        spec["code_arena"]=dict(rva=0x1b000,virtual_size=0x8000,raw_size=0x8000)
        spec["metadata"].update(rva=0x23000,virtual_size=0xa0000,raw_size=0xa0000)
        for name in ("llm.base","llm.count","llm.directory","llm.error"):
            symbols[name]+=0x4000

        nonvolatile=["RBX","RBP","RSI","RDI","R12","R13","R14","R15","XMM6..XMM15"]
        def add_function(name,rva,capacity,f,inputs,returns,purpose,stack=False,contracts=None):
            f.ready(); symbols[name]=rva
            doc=dict(schema="llm-pe.module.v1",name=name,contract_version=1,purpose=purpose,
                abi=dict(platform="Windows x64",inputs=inputs,returns=returns,caller_shadow_bytes=32,
                    nonvolatile_preserved=nonvolatile,clobbers="Win64 volatile registers and flags.",
                    memory_contracts=contracts or ["Data.Combat"]),
                implementation=dict(entry_rva=rva,implementation_rva=rva,used_bytes=len(f.b),
                    slot_bytes=capacity,section=".mods",unwind_profile="stack56" if stack else "leaf",
                    unwind_hex="0104010004620000" if stack else "01000000",gate=None),
                dependencies={},references=f.refs,local_symbols=f.labels,tests=["--test","--smoke"],notes=[])
            m=dict(name=name,kind=1,capacity=8192,code_hex=f.b.hex(),document=doc)
            modules.append(m); by[name]=m; return m

        # CombatReset(ctx): zero exactly 1152 bytes, then write size/version header.
        f=Bytes("combatreset"); f.e("49 89 ca 31 c0")
        f.label("clear"); f.e("41 c6 04 02 00 ff c0 3d 80 04 00 00"); f.j("0f 82","clear")
        f.e("41 c7 02 80 04 00 00 41 c7 42 04 02 00 00 00 c3")
        add_function("CombatReset",0x1b800,0x400,f,{"RCX":"Data.Combat* writable 1152 bytes"},"No register result; first shot ready.",
                     "Reset only the bounded combat context.")

        # MeteorMap(ctx): rebuild 800 hazard cells from up to eight independent cross entities.
        f=Bytes("meteormap"); f.e("49 89 ca 4d 8d 9a e0 00 00 00 31 c0")
        f.label("clear"); f.e("41 c6 04 03 00 ff c0 3d 20 03 00 00"); f.j("0f 82","clear")
        f.e("4d 8d 82 80 00 00 00 41 b9 08 00 00 00")
        f.label("meteor"); f.e("41 83 78 08 00"); f.j("0f 84","next")
        for index,(dx,dy) in enumerate([(0,-1),(-1,0),(0,0),(1,0),(0,1)]):
            f.e("41 8b 08 41 8b 50 04")
            if dx<0:f.e("ff c9")
            if dx>0:f.e("ff c1")
            if dy<0:f.e("ff ca")
            if dy>0:f.e("ff c2")
            f.e("83 f9 32"); f.j("0f 83","skip"+str(index))
            f.e("83 fa 10"); f.j("0f 83","skip"+str(index))
            f.e("6b c2 32 01 c8 41 c6 04 03 01"); f.label("skip"+str(index))
        f.label("next"); f.e("49 83 c0 0c 41 ff c9"); f.j("0f 85","meteor"); f.e("c3")
        add_function("MeteorMap",0x1bc00,0x400,f,{"RCX":"Data.Combat*"},"No result; bounded hazard bitmap rebuilt.",
                     "Rasterize only the five cells of each 3 by 3 cross; clip outside the board.")

        # MeteorFall(ctx): advance entities once per star fall; spawn a cross every ten falls.
        f=Bytes("meteorfall"); f.e("48 83 ec 38 48 89 4c 24 20 4c 8d 81 80 00 00 00 41 b9 08 00 00 00")
        f.label("move"); f.e("41 83 78 08 00"); f.j("0f 84","next")
        f.e("41 ff 40 04 41 83 78 04 11"); f.j("0f 8c","next"); f.e("41 c7 40 08 00 00 00 00")
        f.label("next"); f.e("49 83 c0 0c 41 ff c9"); f.j("0f 85","move")
        f.e("ff 41 10 83 79 10 0a"); f.j("0f 82","map")
        f.e("c7 41 10 00 00 00 00 4c 8d 81 80 00 00 00 41 b9 08 00 00 00")
        f.label("find"); f.e("41 83 78 08 00"); f.j("0f 84","spawn")
        f.e("49 83 c0 0c 41 ff c9"); f.j("0f 85","find"); f.j("e9","map")
        f.label("spawn"); f.e("4c 89 44 24 28"); f.r("e8","Random",kind="call")
        f.e("31 d2 b9 30 00 00 00 f7 f1 ff c2 4c 8b 44 24 28 41 89 10 41 c7 40 04 ff ff ff ff 41 c7 40 08 01 00 00 00")
        f.label("map"); f.e("48 8b 4c 24 20"); f.r("e8","MeteorMap",kind="call"); f.e("48 83 c4 38 c3")
        add_function("MeteorFall",0x1c000,0x400,f,{"RCX":"Data.Combat*"},"No result; crosses advance and hazard map updates.",
                     "Advance indestructible cross entities and spawn every ten fall steps.",True,["Data.Combat","Data.State"])

        # TryFire(ctx,elapsed,x,y): consume no cooldown until a free valid projectile is emitted.
        f=Bytes("tryfire"); f.e("3b 51 08"); f.j("0f 82","no")
        f.e("41 83 f8 32"); f.j("0f 83","no")
        f.e("41 83 f9 01"); f.j("0f 8c","no"); f.e("41 83 f9 10"); f.j("0f 83","no")
        f.e("4c 8d 51 20 b8 08 00 00 00")
        f.label("find"); f.e("41 83 7a 08 00"); f.j("0f 84","fire")
        f.e("49 83 c2 0c ff c8"); f.j("0f 85","find"); f.j("e9","no")
        f.label("fire"); f.e("45 89 02 41 ff c9 45 89 4a 04 41 c7 42 08 01 00 00 00 81 c2 88 13 00 00 89 51 08 ff 41 14 b8 01 00 00 00"); f.j("e9","done")
        f.label("no"); f.e("31 c0"); f.label("done"); f.e("c3")
        add_function("TryFire",0x1c400,0x400,f,{"RCX":"Data.Combat*","EDX":"uint32 survival milliseconds",
            "R8D":"player x, 0..49","R9D":"player y, 0..15"},"EAX 1 emitted, 0 blocked/full/top row/cooldown.",
            "Emit an upward dot at most once every 5000 ms; first shot is ready.")
        by["TryFire"]["document"]["notes"]=["No firing above row zero; failed attempts do not consume cooldown.","Holding Space fires when ready; shot limit is time based, not key edge based."]

        # ProjectileStep(ctx,elapsed,board): resolve old and new cells, prioritizing meteor armor.
        f=Bytes("projectilestep"); f.e("49 89 ca 4d 89 c3 89 d0 41 2b 42 0c 41 c7 42 18 00 00 00 00 83 f8 64")
        f.j("0f 82","timed"); f.e("41 89 52 0c 41 c7 42 18 01 00 00 00")
        f.label("timed"); f.e("4d 8d 42 20 41 b9 08 00 00 00")
        f.label("shot"); f.e("41 83 78 08 00"); f.j("0f 84","next")
        for stage in (0,1):
            if stage==1:
                f.e("41 83 7a 18 00"); f.j("0f 84","next"); f.e("41 ff 48 04")
            f.e("41 8b 50 04 83 fa 10"); f.j("0f 83","remove")
            f.e("41 8b 08 83 f9 32"); f.j("0f 83","remove")
            f.e("6b c2 32 01 c8 41 80 bc 02 e0 00 00 00 00"); f.j("0f 85","remove")
            f.e("41 80 3c 03 00"); f.j("0f 85","destroy")
        f.j("e9","next"); f.label("destroy"); f.e("41 c6 04 03 00")
        f.label("remove"); f.e("41 c7 40 08 00 00 00 00")
        f.label("next"); f.e("49 83 c0 0c 41 ff c9"); f.j("0f 85","shot"); f.e("c3")
        add_function("ProjectileStep",0x1c800,0x400,f,{"RCX":"Data.Combat*","EDX":"uint32 survival milliseconds",
            "R8":"uint8* writable 800-byte star grid"},"No result; dots move at most one row per 100 ms call.",
            "Destroy one star per dot; indestructible crosses absorb the dot.",contracts=["Data.Combat","Data.Board"])
        by["ProjectileStep"]["document"]["notes"]=["Check current cell even without movement so falling objects cannot pass through stationary dots.","Meteor armor is checked before an overlapping star; bullets never change meteor records or bitmap."]

        # CombatDraw(ctx,frame,elapsed): draw HUD, crosses and cyan dots inside the original frame.
        f=Bytes("combatdraw"); f.e("49 89 ca 49 89 d3")
        def draw_word(offset,value): f.e("41 c7 83"); f.u(offset); f.u(value)
        for i,ch in enumerate("FIRE: "): draw_word((2*64+7+i)*4,0x00070000|ord(ch))
        f.e("41 8b 42 08 44 29 c0"); f.j("0f 8e","ready")
        f.e("05 e7 03 00 00 31 d2 b9 e8 03 00 00 f7 f1 83 c0 30 0d 00 00 0b 00 41 89 83"); f.u((2*64+13)*4)
        for i,ch in enumerate(" sec     ",1): draw_word((2*64+13+i)*4,0x000b0000|ord(ch))
        f.j("e9","hazards")
        f.label("ready")
        for i,ch in enumerate("READY     "): draw_word((2*64+13+i)*4,0x000b0000|ord(ch))
        f.label("hazards"); f.e("45 31 c0")
        f.label("cell"); f.e("43 80 bc 02 e0 00 00 00 00"); f.j("0f 84","nextcell")
        f.e("44 89 c0 31 d2 b9 32 00 00 00 f7 f1 83 c0 04 c1 e0 06 01 d0 83 c0 07 41 c7 04 83 23 00 0c 00")
        f.label("nextcell"); f.e("41 ff c0 41 81 f8 20 03 00 00"); f.j("0f 82","cell")
        f.e("4d 8d 42 20 41 b9 08 00 00 00")
        f.label("shot"); f.e("41 83 78 08 00"); f.j("0f 84","nextshot")
        f.e("41 8b 50 04 83 fa 10"); f.j("0f 83","nextshot")
        f.e("41 8b 08 83 f9 32"); f.j("0f 83","nextshot")
        f.e("6b c2 32 01 c8 41 80 bc 02 e0 00 00 00 00"); f.j("0f 85","nextshot")
        f.e("41 8b 40 04 83 c0 04 c1 e0 06 41 03 00 83 c0 07 41 c7 04 83 2e 00 0b 00")
        f.label("nextshot"); f.e("49 83 c0 0c 41 ff c9"); f.j("0f 85","shot"); f.e("c3")
        add_function("CombatDraw",0x1cc00,0x400,f,{"RCX":"const Data.Combat*","RDX":"CHAR_INFO* 1600 cells",
            "R8D":"uint32 survival milliseconds"},"No result; bounded frame cells updated.",
            "Draw five-cell red crosses, cyan projectile dots, and the five-second cooldown HUD.",
            contracts=["Data.Combat","Data.Frame"])

        # Existing public entries stay stable. This is an explicit data/module migration.
        f=Bytes("resetcombat"); f.r("48 8d 0d","combat"); f.r("e8","CombatReset",kind="call")
        splice(by["Reset"],88,88,f)
        by["Reset"]["code_hex"]="4883ec38"+by["Reset"]["code_hex"][:-2]+"4883c438c3"
        # A four-byte frame prefix shifts all Reset references/local targets.
        for ref in by["Reset"]["document"]["references"]:
            ref["offset"]+=4; ref["next_offset"]+=4
            if ref["local"] is not None:ref["local"]+=4
        by["Reset"]["document"]["local_symbols"]={k:v+4 for k,v in by["Reset"]["document"]["local_symbols"].items()}
        by["Reset"]["document"]["implementation"]["unwind_profile"]="stack56"
        by["Reset"]["document"]["implementation"]["unwind_hex"]="0104010004620000"

        f=Bytes("collision"); f.r("8b 05","playerY"); f.e("6b c0 32"); f.r("03 05","playerX")
        f.r("4c 8d 15","board"); f.e("41 80 3c 02 00"); f.j("0f 85","hit")
        f.r("4c 8d 15","combat.hazard"); f.e("41 80 3c 02 00 0f 95 c0 0f b6 c0"); f.j("e9","done")
        f.label("hit"); f.e("b8 01 00 00 00"); f.label("done"); f.e("c3"); f.ready()
        by["Collision"]["code_hex"]=f.b.hex(); by["Collision"]["document"]["references"]=f.refs
        by["Collision"]["document"]["local_symbols"]=f.labels
        by["Collision"]["document"]["purpose"]="Check player cell for a star or a cross meteor."
        by["Collision"]["document"]["abi"]["returns"]="EAX 1 if player overlaps a star or any of five meteor cells, otherwise 0."

        # InputDecode is shared by physical held-key polling and buffered console events.
        f=Bytes("inputdecode"); f.e("31 c0 85 d2"); f.j("0f 84","done")
        groups=[([0x25,0x41],1),([0x27,0x44],2),([0x26,0x57],4),
                ([0x28,0x53],8),([0x0d,0x52],16),([0x20],0x50),([0x1b],32)]
        for i,(keys,mask) in enumerate(groups):
            for key in keys:
                f.e("83 f9");f.e(bytes([key]).hex());f.j("0f 84","bit"+str(i))
        f.j("e9","done")
        for i,(keys,mask) in enumerate(groups):
            f.label("bit"+str(i));f.e("b8");f.u(mask);f.j("e9","done")
        f.label("done");f.e("c3")
        add_function("InputDecode",0x1f000,0x400,f,{"ECX":"uint32 virtual-key code","EDX":"nonzero key down"},"EAX action mask; Space always sets action and fire together.",
            "Decode one key consistently for held polling and queued events.",contracts=["Data.State"])

        # InputEvent consumes one KEY_EVENT_RECORD. Physical bits suppress OS autorepeat.
        f=Bytes("inputevent");f.e("48 83 ec 38 48 89 4c 24 20 66 83 b9 08 04 00 00 01")
        f.j("0f 85","done");f.e("0f b7 81 12 04 00 00 3d 00 01 00 00");f.j("0f 83","done")
        f.e("89 81 30 04 00 00 8b 91 0c 04 00 00 89 91 34 04 00 00 89 c1 ba 01 00 00 00")
        f.r("e8","InputDecode",kind="call")
        f.e("4c 8b 54 24 20 41 89 c3 41 8b 8a 30 04 00 00 41 83 ba 34 04 00 00 00")
        f.j("0f 84","release")
        f.e("41 0f a3 8a 40 04 00 00");f.j("0f 82","done")
        f.e("41 0f ab 8a 40 04 00 00")
        for mask,clear in ((3,0xfffffffc),(12,0xfffffff3)):
            label="axis"+str(mask);f.e("44 89 d8 83 e0");f.e(bytes([mask]).hex())
            f.j("0f 84",label);f.e("41 81 a2 28 04 00 00");f.u(clear)
            f.e("41 09 82 28 04 00 00");f.label(label)
        f.e("41 83 e3 70 45 09 9a 1c 04 00 00");f.j("e9","done")
        f.label("release");f.e("41 0f b3 8a 40 04 00 00")
        f.label("done");f.e("48 83 c4 38 c3")
        add_function("InputEvent",0x1f400,0x400,f,{"RCX":"Data.Combat*; one INPUT_RECORD at offset 1032"},"No result; pending press pulses and physical key bits updated.",
            "Retain quick presses across key-up and ignore autorepeat movement pulses.",True)
        by["InputEvent"]["document"]["notes"]=["Latest press wins per movement axis; release does not erase an unconsumed pulse.","Physical bitmap indexes VK 0..255; BT/BTS/BTR bounds are checked before access."]

        f=Bytes("readkeys");f.e("48 83 ec 38 48 89 4c 24 20 48 89 54 24 28 48 89 d1")
        f.e("48 8b 54 24 20 48 81 c2 00 04 00 00");f.r("ff 15","iat.GetNumberOfConsoleInputEvents",kind="import")
        f.e("85 c0");f.j("0f 84","done");f.e("4c 8b 54 24 20 41 8b 82 00 04 00 00 85 c0")
        f.j("0f 84","done");f.e("83 f8 10");f.j("0f 86","bounded");f.e("b8 10 00 00 00")
        f.label("bounded");f.e("41 89 82 24 04 00 00")
        f.label("read");f.e("48 8b 4c 24 28 4c 8b 54 24 20 49 8d 92 08 04 00 00 41 b8 01 00 00 00 4d 8d 8a 04 04 00 00")
        f.r("ff 15","iat.ReadConsoleInputW",kind="import")
        f.e("85 c0");f.j("0f 84","done");f.e("48 8b 4c 24 20 83 b9 04 04 00 00 01")
        f.j("0f 85","done");f.r("e8","InputEvent",kind="call")
        f.e("4c 8b 54 24 20 41 ff 8a 24 04 00 00");f.j("0f 85","read")
        f.label("done");f.e("48 83 c4 38 c3")
        add_function("ReadKeyEvents",0x1f800,0x400,f,{"RCX":"Data.Combat*","RDX":"borrowed console input HANDLE"},"No result; up to 16 existing records consumed; invalid handle is harmless.",
            "Read a bounded snapshot of queued console events without waiting on an empty queue.",True,["Data.Combat","Data.Console"])
        by["ReadKeyEvents"]["document"]["notes"]=["Single consumer owns this input queue; count before reading one record at a time.","Mouse/window records consume the budget but are ignored by InputEvent."]

        f=Bytes("movementgate");f.e("44 89 c8 83 e0 0f 44 8b 91 20 04 00 00 89 81 20 04 00 00 44 8b 99 28 04 00 00 c7 81 28 04 00 00 00 00 00 00")
        f.e("45 85 db");f.j("0f 85","yes")
        f.e("41 f7 d2 41 21 c2 45 85 d2");f.j("0f 85","yes")
        f.e("85 c0");f.j("0f 84","no");f.e("4c 29 c2 48 83 fa 4b");f.j("0f 83","yes")
        f.label("no");f.e("31 c0 c3");f.label("yes");f.e("b8 01 00 00 00 c3")
        add_function("MovementGate",0x1fc00,0x400,f,{"RCX":"Data.Combat*","RDX":"uint64 current uptime ms",
            "R8":"uint64 previous movement uptime ms","R9D":"current action mask"},"EAX 1 move this frame, 0 wait.",
            "Move immediately on a fresh press or buffered tap; held movement repeats every 75 ms.")
        by["MovementGate"]["document"]["notes"]=["Consumes pending movement pulse; previous physical mask is updated every frame.","No wall-clock access: native tests pass deterministic timestamps."]

        # Keys has a complete independent slot; no inserted branch can bypass Space.
        f=Bytes("keys");f.e("48 83 ec 38");f.r("c7 05","input","00000000")
        f.r("48 8b 05","window");f.e("48 85 c0");f.j("0f 84","poll")
        f.r("ff 15","iat.GetForegroundWindow",kind="import");f.r("48 3b 05","window");f.j("0f 85","done")
        f.label("poll")
        for vk in (0x25,0x41,0x27,0x44,0x26,0x57,0x28,0x53,0x0d,0x20,0x52,0x1b):
            f.e("b9");f.u(vk);f.r("ff 15","iat.GetAsyncKeyState",kind="import")
            f.e("89 c2 81 e2 00 80 00 00 b9");f.u(vk);f.r("e8","InputDecode",kind="call")
            f.r("09 05","input")
        f.r("48 8d 0d","combat");f.r("48 8b 15","hin");f.r("e8","ReadKeyEvents",kind="call")
        f.r("4c 8d 15","combat");f.r("8b 05","input")
        for mask,clear in ((3,0xfffffffc),(12,0xfffffff3)):
            label="merge"+str(mask);f.e("41 8b 92 28 04 00 00 83 e2");f.e(bytes([mask]).hex())
            f.j("0f 84",label);f.e("25");f.u(clear);f.e("09 d0");f.label(label)
        f.e("41 0b 82 1c 04 00 00 41 c7 82 1c 04 00 00 00 00 00 00");f.r("89 05","input")
        f.label("done");f.e("48 83 c4 38 c3");f.ready()
        by["Keys"]["code_hex"]=f.b.hex();by["Keys"]["document"]["references"]=f.refs
        by["Keys"]["document"]["local_symbols"]=f.labels
        by["Keys"]["document"]["purpose"]="Focus-gated held polling plus buffered key events, with unified Space action/fire decoding."
        by["Keys"]["document"]["abi"]["memory_contracts"].append("Data.Combat")

        def projectile_call(prefix):
            f=Bytes(prefix); f.r("48 8d 0d","combat"); f.r("8b 15","elapsed")
            f.r("4c 8d 05","board"); f.r("e8","ProjectileStep",kind="call"); return f
        f=Bytes("tickmeteor"); f.r("48 8d 0d","combat"); f.r("e8","MeteorFall",kind="call")
        g=projectile_call("tickafterfall")
        for ref in g.refs:ref["offset"]+=len(f.b); ref["next_offset"]+=len(f.b)
        f.refs.extend(g.refs); f.b.extend(g.b)
        splice(by["Tick"],220,220,f)
        f=Bytes("tickfire"); f.r("8b 05","input"); f.e("a9 40 00 00 00"); f.j("0f 84","shots")
        f.r("48 8d 0d","combat"); f.r("8b 15","elapsed"); f.r("44 8b 05","playerX"); f.r("44 8b 0d","playerY")
        f.r("e8","TryFire",kind="call"); f.label("shots")
        g=projectile_call("tickshots")
        for ref in g.refs:ref["offset"]+=len(f.b); ref["next_offset"]+=len(f.b)
        f.refs.extend(g.refs); f.b.extend(g.b)
        splice(by["Tick"],151,151,f,preserve_label=True)

        f=Bytes("tickinput");f.r("48 8d 0d","combat");f.r("48 8b 15","now")
        f.r("4c 8b 05","lastMove");f.r("44 8b 0d","input");f.r("e8","MovementGate",kind="call")
        f.e("85 c0");f.r("0f 84","tick.collision",kind="branch")
        splice(by["Tick"],46,70,f)
        by["Tick"]["document"]["purpose"]="Immediate press movement, timed held movement, combat and bounded star catch-up."

        f=Bytes("framecombat"); f.r("48 8d 0d","combat"); f.r("48 8d 15","frame"); f.r("44 8b 05","elapsed")
        f.r("e8","CombatDraw",kind="call"); f.r("4c 8d 1d","frame")
        splice(by["BuildFrame"],184,184,f)
        code=bytes.fromhex(by["BuildFrame"]["code_hex"])
        assert code.count(bytes.fromhex("41c7048340000a00"))==1
        by["BuildFrame"]["code_hex"]=code.replace(bytes.fromhex("41c7048340000a00"),bytes.fromhex("41c704835e000a00")).hex()
        code=bytes.fromhex(by["Tests"]["code_hex"])
        assert code.count(bytes.fromhex("ba40000a00"))==1
        by["Tests"]["code_hex"]=code.replace(bytes.fromhex("ba40000a00"),bytes.fromhex("ba5e000a00")).hex()

        # Console integration covers multiple shots and compares rate against real elapsed time.
        smoke_code=bytearray.fromhex(by["Smoke"]["code_hex"])
        for ref in by["Smoke"]["document"]["references"]:
            if ref["target"]=="smokeFrames":
                struct.pack_into("<I",smoke_code,ref["next_offset"]-4,400)
            if ref["target"]=="input":
                struct.pack_into("<I",smoke_code,ref["next_offset"]-4,0x42)
        by["Smoke"]["code_hex"]=smoke_code.hex()
        f=Bytes("smokecombatsetup")
        # Own hidden console queue: do not send desktop keystrokes or steal user focus.
        symbols["combat.window_saved"]=symbols["combat"]+1120
        symbols["combat.input_saved"]=symbols["combat"]+1128
        ro_string("combat.conin","C\0O\0N\0I\0N\0$\0\0")
        ro_string("combat.smoke.input","own console input buffer opened for key regression\r\n")
        f.r("48 8b 05","hin");f.r("48 89 05","combat.input_saved")
        f.r("48 8d 0d","combat.conin");f.e("ba 00 00 00 c0 41 b8 03 00 00 00 45 31 c9")
        f.e("c7 44 24 20 03 00 00 00 c7 44 24 28 00 00 00 00 48 c7 44 24 30 00 00 00 00")
        f.r("ff 15","iat.CreateFileW",kind="import");f.r("48 89 05","hin")
        f.e("48 83 f8 ff 0f 95 c0 0f b6 c0 ba 01 00 00 00");f.r("48 8d 0d","combat.smoke.input");f.r("e8","Assert",kind="call")
        f.r("48 8b 05","window");f.r("48 89 05","combat.window_saved");f.r("48 c7 05","window","00000000")
        for name in ("combat.smoke.A","combat.smoke.D","combat.smoke.Space"):
            ro_string(name,{"combat.smoke.A":"real console quick A tap moves immediately\r\n",
                "combat.smoke.D":"real console quick D reversal moves immediately\r\n",
                "combat.smoke.Space":"real console Space tap emits a dot\r\n"}[name])
        for vk,label,target,expected in ((0x41,"combat.smoke.A","playerX",24),(0x44,"combat.smoke.D","playerX",25),
                                       (0x20,"combat.smoke.Space","combat.20",1)):
            for down in (1,0):
                f.r("48 8d 15","combat");f.e("c7 82 08 04 00 00 01 00 00 00 c7 82 0c 04 00 00");f.u(down)
                f.e("c7 82 10 04 00 00");f.u((vk<<16)|1)
                f.e("48 81 c2 08 04 00 00");f.r("48 8b 0d","hin")
                f.e("41 b8 01 00 00 00");f.r("4c 8d 0d","combat.input_read")
                f.r("ff 15","iat.WriteConsoleInputW",kind="import")
            f.r("e8","Keys",kind="call");f.r("e8","Tick",kind="call")
            f.r("8b 05",target);f.e("ba");f.u(expected);f.r("48 8d 0d",label);f.r("e8","Assert",kind="call")
        f.r("48 8b 0d","hin");f.r("ff 15","iat.CloseHandle",kind="import")
        f.r("48 8b 05","combat.input_saved");f.r("48 89 05","hin")
        f.r("48 8b 05","combat.window_saved");f.r("48 89 05","window")
        f.r("e8","Start",kind="call")
        f.r("48 8d 0d","combat")
        f.e("c7 81 80 00 00 00 19 00 00 00 c7 81 84 00 00 00 00 00 00 00 c7 81 88 00 00 00 01 00 00 00")
        f.r("e8","MeteorMap",kind="call")
        symbols["combat.input_read"]=symbols["combat"]+1028
        # Append assertions before the summary first; setup offsets remain original.
        ro_string("combat.smoke.shots","console respects five-second shot rate\r\n")
        ro_string("combat.smoke.meteor","cross meteor survives real console simulation\r\n")
        symbols["combat.20"]=symbols["combat"]+20
        f2=Bytes("smokecombatchecks");f2.r("44 8b 15","combat.20");f2.e("41 83 fa 02 41 0f 93 c3")
        f2.r("8b 05","elapsed");f2.e("31 d2 b9 88 13 00 00 f7 f1 ff c0 41 39 c2 0f 96 c0 44 20 d8 0f b6 c0 ba 01 00 00 00")
        f2.r("48 8d 0d","combat.smoke.shots");f2.r("e8","Assert",kind="call")
        f2.r("4c 8d 15","combat.hazard");f2.e("31 c0 b9 20 03 00 00")
        f2.label("sum");f2.e("41 0f b6 12 01 d0 49 ff c2 ff c9");f2.j("0f 85","sum")
        f2.e("85 c0 0f 95 c0 0f b6 c0 ba 01 00 00 00")
        f2.r("48 8d 0d","combat.smoke.meteor");f2.r("e8","Assert",kind="call")
        splice(by["Smoke"],382,382,f2)
        splice(by["Smoke"],145,145,f)
        by["Smoke"]["document"]["purpose"]="Real console queued A/D/Space taps and 400 rendered combat frames."
        by["Smoke"]["document"]["notes"].append("Input holds Right and Space for 400 frames; require at least two shots within the elapsed-time firing bound.")

        # Native regression assertions call the same production combat functions.
        tests=Bytes("combattests"); tests.e("48 83 ec 38"); test_names=[]
        def call(name): tests.r("e8",name,kind="call")
        def ctx():tests.r("48 8d 0d","combat")
        def set32(offset,value):
            tests.r("c7 05","combat" if offset==0 else "combat."+str(offset),struct.pack("<I",value&0xffffffff).hex())
            symbols["combat."+str(offset)]=symbols["combat"]+offset
        def read32(offset):
            symbols["combat."+str(offset)]=symbols["combat"]+offset
            tests.r("8b 05","combat."+str(offset))
        def readbyte(name):tests.r("0f b6 05",name)
        def check(name,expected):
            label="combat.test."+str(len(test_names)+1); ro_string(label,name+"\r\n"); test_names.append(name)
            tests.e("ba");tests.u(expected);tests.r("48 8d 0d",label);call("Assert")
        def reset():call("Reset")
        def fire(time,x=25,y=14):
            ctx();tests.e("ba");tests.u(time);tests.e("41 b8");tests.u(x);tests.e("41 b9");tests.u(y);call("TryFire")
        def step(time):
            ctx();tests.e("ba");tests.u(time);tests.r("4c 8d 05","board");call("ProjectileStep")
        def shot(x,y):set32(32,x);set32(36,y);set32(40,1)
        def meteor(x,y):set32(128,x);set32(132,y);set32(136,1);ctx();call("MeteorMap")
        def star(x,y,value=1):
            name="combat.star."+str(y*50+x);symbols[name]=symbols["board"]+y*50+x
            tests.r("c6 05",name,bytes([value]).hex());return name
        def hazard(x,y):
            name="combat.cell."+str(y*50+x);symbols[name]=symbols["combat.hazard"]+y*50+x;return name
        def map_count():
            tests.r("4c 8d 15","combat.hazard");tests.e("31 c0 b9 20 03 00 00")
            label="sum"+str(len(test_names));tests.label(label)
            tests.e("41 0f b6 12 01 d0 49 ff c2 ff c9");tests.j("0f 85",label)
        def framecell(x,y):
            name="combat.frame."+str(y*50+x)
            symbols[name]=symbols["frame"]+((y+4)*64+x+7)*4
            return name
        reset();read32(0);check("combat context size",1152);read32(4);check("combat contract version",2)
        fire(0);check("first shot is ready",1);read32(8);check("shot cooldown is 5000 ms",5000)
        read32(32);check("shot inherits player column",25);read32(36);check("shot begins above player",13)
        fire(4999);check("shot blocked before five seconds",0)
        fire(5000);check("shot accepted at five seconds",1);read32(20);check("only two shots emitted",2)
        reset();read32(40);check("restart clears projectiles",0);read32(8);check("restart clears cooldown",0)
        fire(0,25,0);check("top row does not emit out of bounds",0);read32(8);check("blocked top shot keeps cooldown ready",0)
        reset();shot(10,2);name=star(10,1);step(100);readbyte(name);check("moving dot destroys star",0)
        read32(40);check("star hit consumes dot",0)
        reset();shot(10,2);name=star(10,2);second=star(10,1);step(0)
        readbyte(name);check("same-cell star hit is immediate",0);readbyte(second);check("one shot does not pierce a second star",1)
        reset();shot(10,5);step(99);read32(36);check("dot waits for 100 ms cadence",5)
        step(100);read32(36);check("dot moves upward one row",4)
        reset();shot(10,0);step(100);read32(40);check("dot expires beyond top edge",0)
        reset();meteor(10,5);map_count();check("meteor is exactly five cells",5)
        for x,y,name in [(10,4,"top"),(9,5,"left"),(10,5,"center"),(11,5,"right"),(10,6,"bottom")]:
            readbyte(hazard(x,y));check("cross "+name+" cell",1)
        readbyte(hazard(9,4));check("cross corner stays empty",0)
        tests.r("c7 05","playerX","0a000000");tests.r("c7 05","playerY","05000000")
        call("Collision");check("meteor center collides with player",1)
        tests.r("c7 05","playerX","09000000");tests.r("c7 05","playerY","04000000")
        call("Collision");check("empty cross corner is safe",0)
        shot(9,5);step(0);read32(40);check("meteor absorbs the dot",0)
        read32(136);check("meteor survives the shot",1);map_count();check("shot cannot damage cross shape",5)
        # Draw both a visible dot and an intact cross through production BuildFrame.
        shot(20,8);call("BuildFrame")
        tests.r("8b 05",framecell(10,5));check("meteor renders as red hash",0x000c0023)
        tests.r("8b 05",framecell(20,8));check("projectile renders as cyan dot",0x000b002e)
        tests.r("8b 05",framecell(9,4));check("player renders as green caret",0x000a005e)
        ctx();call("MeteorFall");read32(132);check("meteor falls by one row",6)
        reset();meteor(10,16);map_count();check("bottom edge clips cross to one cell",1)
        ctx();call("MeteorFall");read32(136);check("meteor retires below board",0);map_count();check("retired meteor leaves no hazard",0)
        reset();meteor(10,0);map_count();check("top edge clips cross to four cells",4)
        tests.r("c7 05","combat.guard","bebafeca");ctx();call("MeteorMap")
        tests.r("8b 05","combat.guard");check("hazard map preserves its end guard",0xcafebabe)
        reset();set32(16,8);ctx();call("MeteorFall");read32(136);check("meteor not spawned before ten falls",0)
        ctx();call("MeteorFall");read32(136);check("meteor spawns on tenth fall",1)
        read32(132);check("new meteor enters from above",0xffffffff)
        read32(128);tests.e("83 f8 01 0f 93 c1 83 f8 30 0f 96 c0 20 c8 0f b6 c0");check("meteor spawn stays inside three-wide bounds",1)
        # Regress live input semantics rather than bypassing Keys with a synthetic mask.
        def decode(vk,down=1):
            tests.e("b9");tests.u(vk);tests.e("ba");tests.u(down);call("InputDecode")
        for vk,expected,label in [(0x20,0x50,"Space includes fire"),(0x41,1,"A moves left"),(0x44,2,"D moves right"),
                (0x25,1,"left arrow"),(0x27,2,"right arrow"),(0x57,4,"W moves up"),(0x53,8,"S moves down"),
                (0x0d,16,"Enter starts"),(0x1b,32,"Escape quits"),(0x58,0,"unmapped key")]:
            decode(vk);check(label,expected)
        decode(0x20,0);check("released Space is not held",0)
        def event(vk,down=1,event_type=1):
            set32(1032,event_type);set32(1036,down);set32(1040,(vk<<16)|1);ctx();call("InputEvent")
        reset();event(0x20);read32(1052);check("queued Space includes fire",0x50)
        event(0x20,0);read32(1052);check("quick Space release preserves pending shot",0x50)
        read32(1092);check("Space release clears physical bit",0)
        reset();event(0x41);read32(1064);check("queued A retains tap",1)
        set32(1064,0);event(0x41);read32(1064);check("autorepeat does not create new movement pulse",0)
        event(0x41,0);event(0x41);read32(1064);check("second A tap creates a new pulse",1)
        event(0x44);read32(1064);check("latest horizontal tap wins",2)
        event(0x57);read32(1064);check("independent vertical tap is retained",6)
        reset();event(0x41,1,2);read32(1064);check("non-key console event is ignored",0)
        event(0x100);read32(1064);check("out of range virtual key is ignored",0)
        def gate(now,last,mask):
            ctx();tests.e("ba");tests.u(now);tests.e("41 b8");tests.u(last);tests.e("41 b9");tests.u(mask);call("MovementGate")
        reset();gate(0,0,1);check("first A press moves immediately",1)
        gate(74,0,1);check("held A waits below repeat interval",0)
        gate(75,0,1);check("held A moves at repeat interval",1)
        gate(80,75,0);check("released movement stops",0)
        gate(81,75,2);check("new D press moves immediately",1)
        gate(82,81,1);check("direction reversal moves immediately",1)
        set32(1064,1);gate(83,82,1);check("quick repeated A tap moves immediately",1)
        read32(1064);check("movement gate consumes tap once",0)
        gate(84,83,1);check("consumed tap does not repeat next frame",0)
        ctx();tests.e("48 c7 c2 ff ff ff ff");call("ReadKeyEvents")
        read32(1064);check("invalid console handle returns without pending input",0)
        reset();tests.e("48 83 c4 38 c3")
        m=add_function("CombatTests",0x1d000,0x2000,tests,{},"No register result; logs assertions through Assert.",
            "Native tests for combat and deterministic key decoding, queued presses, autorepeat and immediate movement.",True,
            ["Data.Combat","Data.State","Data.Board","Data.Frame","Data.Testing"])
        m["capacity"]=65536;m["document"]["notes"]=test_names
        f=Bytes("testscombat");f.r("e8","CombatTests",kind="call")
        splice(by["Tests"],2332,2332,f)

        contract=dict(schema="llm-pe.module.v1",name="Data.Combat",contract_version=2,
            purpose="Bounded combat context passed explicitly to new native functions.",rva=0x18000,size=1152,alignment=8,
            ownership="Single game thread; reset for each run. No score-storage format change.",
            fields=[
                dict(name="size_bytes",offset=0,type="uint32",value=1152),
                dict(name="abi_major",offset=4,type="uint32",value=2),
                dict(name="next_shot_ms",offset=8,type="uint32",units="survival milliseconds"),
                dict(name="last_projectile_step_ms",offset=12,type="uint32"),
                dict(name="meteor_fall_counter",offset=16,type="uint32",invariant="0..9"),
                dict(name="shots_fired",offset=20,type="uint32"),
                dict(name="step_due",offset=24,type="uint32",invariant="0 or 1"),
                dict(name="reserved",offset=28,type="uint32"),
                dict(name="shots",offset=32,type="Shot[8]",element_size=12),
                dict(name="meteors",offset=128,type="Meteor[8]",element_size=12),
                dict(name="hazard",offset=224,type="uint8[16][50]",invariant="0 or 1, read only to projectiles"),
                dict(name="input_count",offset=1024,type="uint32"),dict(name="input_read",offset=1028,type="uint32"),
                dict(name="input_record",offset=1032,type="INPUT_RECORD",size=20),
                dict(name="pending_actions",offset=1052,type="uint32"),dict(name="previous_motion",offset=1056,type="uint32"),
                dict(name="event_budget",offset=1060,type="uint32",invariant="0..16"),dict(name="pending_motion",offset=1064,type="uint32"),
                dict(name="scratch_vk",offset=1072,type="uint32"),dict(name="scratch_down",offset=1076,type="uint32"),
                dict(name="physical_keys",offset=1088,type="uint8[32]",invariant="one bit per VK 0..255"),
                dict(name="reserved_tail",offset=1120,type="uint8[32]")
            ],
            entity_layout=dict(x=dict(offset=0,type="int32"),y=dict(offset=4,type="int32"),active=dict(offset=8,type="uint32")),
            invariants=["Stars remain in their existing 800-byte grid.","Meteor coordinates describe the center of a five-cell 3 by 3 cross.",
                        "Meteor x 1..48; y -1..16 while active; clip every map/draw write.",
                        "Shot cooldown 5000 ms; upward step cadence 100 ms; no frame-rate-dependent firing.",
                        "Header is initialized by CombatReset; intro rendering accepts the initial zeroed context."],
            test_guard=dict(rva=0x18480,type="uint32",ownership="CombatTests only, outside the context"),
            readers=["TryFire","ProjectileStep","MeteorMap","MeteorFall","CombatDraw","Collision","Keys","InputEvent","ReadKeyEvents","MovementGate"],
            writers=["CombatReset","TryFire","ProjectileStep","MeteorMap","MeteorFall","Keys","InputEvent","ReadKeyEvents","MovementGate"])
        modules.insert(9,dict(name="Data.Combat",kind=2,capacity=8192,document=contract))
        by["Data.Console"]["document"]["input_events"]="Single game thread consumes a bounded queue snapshot; held keys use GetAsyncKeyState high bit. Smoke opens its own CONIN$ if redirected stdin is a pipe."
        by["Data.Console"]["document"]["contract_version"]=2
        by["Data.State"]["document"]["contract_version"]=2
        for field in by["Data.State"]["document"]["fields"]:
            if field["name"]=="input":field["invariant"]="bit 0 left;1 right;2 up;3 down;4 action;5 escape;6 Space fire"
        by["Data.Board"]["document"]["mapping"]="Interior console x+7,y+4; player ^; stars *; meteors use separate Data.Combat hazard map."
        by["Data.Board"]["document"]["writers"].append("ProjectileStep")
        by["Data.Board"]["document"]["contract_version"]=2
        by["Data.Frame"]["document"]["contract_version"]=2
        by["Data.Frame"]["document"]["colors"].update(projectiles=11,meteors=12)
        by["Data.Frame"]["document"]["writers"].append("CombatDraw")
        by["Data.Frame"]["document"]["aliases"]={k:v for k,v in by["Data.Frame"]["document"]["aliases"].items() if not k in by["BuildFrame"]["document"]["local_symbols"]}
        by["Data.Testing"]["document"]["native_unit_assertions"]=51+len(test_names)
        architecture=by["Architecture"]["document"]
        architecture["contract_version"]=2
        architecture["purpose"]="Starfall with a caret player, rare upward shots and indestructible cross meteors."
        architecture["gameplay"]=dict(player="^",fire="Space, hold or press; one shot per 5000 ms",
            projectile=".",stars="*; one projectile destroys one star",meteor="five # cells in a 3 by 3 cross; absorbs shots",
            meteor_spawn="one cross every ten fall steps",projectile_step_ms=100)
        architecture["validation"]=dict(native_unit_assertions=51+len(test_names),native_smoke_assertions=11,native_smoke_frames=400)
        architecture["modules"]=[m["name"] for m in modules if m["kind"]==1]
        architecture["design"]["growth"]=dict(code_section=".mods",code_rva=0x1b000,code_bytes=0x8000,metadata_section=".llm",metadata_rva=0x23000,metadata_bytes=0xa0000,directory_capacity=128)
        architecture["design"]["data"]="Legacy globals keep their RVAs; new combat functions accept an explicit 1152-byte context pointer."
        architecture["commands"]={k:v.replace("Starfall-v2.exe","Starfall.exe") for k,v in architecture["commands"].items()}
        architecture["module_count"]=len(modules)
        architecture["reserve_profile"]=dict(code_bytes=0x8000,metadata_bytes=0xa0000,unwind_entries=48)
        architecture["migration"]="Explicit v3 combat/input data, function and import migration; all v2 public function RVAs remain stable."
        architecture["gameplay"]["movement"]="Queued quick taps move immediately; held arrows/WASD repeat every 75 ms."
        architecture["input_regressions"]=["Space decoding cannot be skipped by a prior key branch.","Console key-down/up pairs preserve quick taps.","Held movement remains rate limited; fresh presses and direction changes are immediate."]
        for name in ("Reset","Collision","Keys","Tick","BuildFrame","Tests","Smoke"):
            d=by[name]["document"];d["contract_version"]=2
            if name!="Keys":
                d["abi"]["memory_contracts"]=list(dict.fromkeys(d["abi"]["memory_contracts"]+["Data.Combat"]))
            d["notes"].append("Combat v3 migration preserves this public entry while extending behavior.")
        for m in modules:
            if m["kind"]!=1:continue
            d=m["document"]; code=bytes.fromhex(m["code_hex"]); d["implementation"]["used_bytes"]=len(code)
            if len(code)>d["implementation"]["slot_bytes"]:raise ValueError("Code reserve exhausted: "+m["name"])
            # Public symbols stay stable; local symbol records follow the updated implementation.
            for name,offset in d["local_symbols"].items():symbols[name]=d["implementation"]["implementation_rva"]+offset
            refs=d["references"]
            d["dependencies"]=dict(
                functions=sorted({r["target"] for r in refs if r["kind"]=="call"}),
                imports=sorted({r["target"].removeprefix("iat.") for r in refs if r["kind"]=="import"}),
                memory_symbols=sorted({r["target"] for r in refs if r["kind"]=="rip"}),
                contracts=d["abi"]["memory_contracts"])
            m["capacity"]=max(m["capacity"],wb.align(len(wb.canonical(d))+4096,4096))
        for name,value in by["Data.Frame"]["document"]["aliases"].items():
            if name in symbols:by["Data.Frame"]["document"]["aliases"][name]=symbols[name]
        # Extend imports with a second KERNEL32 descriptor; old IAT RVAs remain stable.
        def allocate(payload,alignment=8):
            nonlocal cursor
            cursor=wb.align(cursor,alignment);at=cursor;cursor+=len(payload)
            if cursor>len(rdata):raise ValueError("Read-only reserve exhausted by import migration")
            rdata[at:cursor]=payload
            return 0x11000+at
        old_import=struct.unpack_from("<II",headers,pe.opt_offset+112+8)[0]
        old_desc=bytes(rdata[old_import-0x11000:old_import-0x11000+40])
        kernel_name=struct.unpack_from("<I",old_desc,12)[0]
        new_apis=["GetNumberOfConsoleInputEvents","ReadConsoleInputW","WriteConsoleInputW"]
        name_rvas=[allocate(b"\0\0"+name.encode("ascii")+b"\0",2) for name in new_apis]
        thunks=b"".join(struct.pack("<Q",rva) for rva in name_rvas)+b"\0"*8
        ilt=allocate(thunks);iat=allocate(thunks)
        for index,name in enumerate(new_apis):symbols["iat."+name]=iat+index*8
        imports=allocate(old_desc+struct.pack("<IIIII",ilt,0,0,kernel_name,iat)+b"\0"*20)
        symbols["imports"]=imports
        struct.pack_into("<II",headers,pe.opt_offset+112+8,imports,80)
        old_iat,old_size=struct.unpack_from("<II",headers,pe.opt_offset+112+12*8)
        struct.pack_into("<II",headers,pe.opt_offset+112+12*8,old_iat,iat+len(thunks)-old_iat)
        import_doc=by["Architecture"]["document"]
        import_doc["contract_version"]=2
        import_doc["notes"]=import_doc.get("notes",[])+["Input migration adds a second KERNEL32 descriptor while retaining original IAT RVAs."]
        import_doc["input_apis"]=dict(GetNumberOfConsoleInputEvents="RCX HANDLE, RDX DWORD* -> BOOL",
            ReadConsoleInputW="RCX HANDLE, RDX INPUT_RECORD*, R8D count, R9 DWORD* -> BOOL",
            WriteConsoleInputW="RCX HANDLE, RDX const INPUT_RECORD*, R8D count, R9 DWORD* -> BOOL; own-console smoke only")
        # Rewrite physical section offsets; original code/data/import-slot RVAs remain stable.
        cursor_file=len(headers)
        for index,section in enumerate(sections):
            cursor_file=wb.align(cursor_file,pe.file_align);section["raw_offset"]=cursor_file
            if section["name"]==".rdata":raw_sections[".rdata"]=rdata
            struct.pack_into("<IIII",headers,pe.table_offset+index*40+8,
                section["virtual_size"],section["rva"],section["raw_size"],section["raw_offset"])
            cursor_file+=section["raw_size"]
        old_initialized=struct.unpack_from("<I",headers,pe.opt_offset+8)[0]
        struct.pack_into("<I",headers,pe.opt_offset+8,old_initialized+0x1800)
        new_base=bytearray(cursor_file);new_base[:len(headers)]=headers
        for section in sections:
            raw=raw_sections[section["name"]]
            new_base[section["raw_offset"]:section["raw_offset"]+section["raw_size"]]=raw
    base_path=arch/"combat-base.exe"
    base_path.write_bytes(new_base)
    spec["base_file"]="architecture/combat-base.exe";spec["output_file"]="Starfall.exe"
    spec["schema"]="llm-pe.migration.v1"
    spec_path=arch/"migration.json";spec_path.write_bytes(wb.canonical(spec))
    output=out/"Starfall.exe"
    wb.migrate(spec_path,output)
    print(json.dumps(dict(native_assertions=51+len(test_names),combat_assertions=len(test_names),
        functions=sum(m["kind"]==1 for m in modules),modules=len(modules),output=str(output),
        new_functions={m["name"]:len(bytes.fromhex(m["code_hex"])) for m in modules if m["name"] in
            ("CombatReset","MeteorMap","MeteorFall","TryFire","ProjectileStep","CombatDraw","CombatTests")}),indent=2))

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workbench",required=True);parser.add_argument("--source",required=True)
    parser.add_argument("--directory",required=True)
    build(parser.parse_args())
