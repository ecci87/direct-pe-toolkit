#!/usr/bin/env python3
"""Starfall v4: explicit x64 bytes and a deliberate pickup/data migration."""
import argparse, copy, importlib.util, json, struct
from pathlib import Path

def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def build(args):
    wb=load_module("wb",args.workbench)
    raw=load_module("raw",Path(args.workbench).with_name("raw_bytes.py"))
    class B(raw.ByteBlock):
        def __init__(self,prefix):super().__init__();self.prefix=prefix
        def e(self,h):self.emit(h);return self
        def u(self,n):self.emit(struct.pack("<I",n&0xffffffff));return self
        def l(self,n):self.label(self.prefix+"."+n)
        def r(self,h,target,tail="",kind="rip"):self.relative(h,target,tail,kind);return self
        def j(self,h,target):self.r(h,self.prefix+"."+target,kind="branch")
        def call(self,name):self.r("e8",name,kind="call")
    source=Path(args.source);out=Path(args.directory);arch=out/"architecture";arch.mkdir(parents=True,exist_ok=True)
    spec=json.loads((source/"migration-v3.json").read_text(encoding="utf-8"))
    modules=spec["modules"];by={m["name"]:m for m in modules};symbols=by["Symbols"]["document"]["symbols"]
    baseline=source/"combat-base.exe";base=bytearray(baseline.read_bytes())
    with wb.PE(baseline,metadata=False) as pe:
        rdata=next(s for s in pe.sections if s["name"]==".rdata")
        imp,size=struct.unpack_from("<II",base,pe.opt_offset+112+8)
        cursor=imp+size
        def string(name,text):
            nonlocal cursor
            payload=(text+"\0").encode("ascii")
            if cursor+len(payload)>rdata["rva"]+rdata["raw_size"]:raise ValueError("String reserve exhausted")
            symbols[name]=cursor;at=pe.offset(cursor);base[at:at+len(payload)]=payload;cursor+=len(payload)
        def old_string(name,text):
            at=pe.offset(symbols[name]);end=base.index(0,at)
            if len(text)>end-at:raise ValueError(name+" reserve")
            base[at:end]=text.ljust(end-at).encode("ascii")
        old_string("welcome2"," Collect F / P. Dodge debris! ")
        template=pe.offset(symbols["template"])
        for row,text in {
            22:"       ARROWS / WASD: MOVE    SPACE: FIRE",
            23:"       F: FAST FIRE   P: POWER SHOTS   Collect pickups",
            24:"       ^ YOU  * STARS  # METEORS   R: RESTART  ESC: QUIT",
        }.items():
            for x,char in enumerate(text.ljust(64)):struct.pack_into("<H",base,template+(row*64+x)*4,ord(char))
        symbols.update({"upgrades":0x18500,"upgrades.fast":0x18508,"upgrades.power":0x1850c,
                        "upgrades.damage":0x18558,"upgrades.guard":0x18600})
        for offset in range(0,120,4):symbols["upgrades."+str(offset)]=0x18500+offset
        def replace(name,f,purpose=None,stack=None):
            m=by[name];d=m["document"];manifest=f.manifest()
            m["code_hex"]=manifest["code_hex"];d["references"]=manifest["references"];d["local_symbols"]=manifest["local_symbols"]
            d["implementation"]["used_bytes"]=len(f.code)
            if purpose:d["purpose"]=purpose
            if stack is not None:
                d["implementation"]["unwind_profile"]="stack56" if stack else "leaf"
                d["implementation"]["unwind_hex"]="0104010004620000" if stack else "01000000"
            return m
        def insert(name,label,fragment,mode="include"):
            m=by[name];block=raw.ByteBlock.from_module(m["document"],m["code_hex"])
            block.insert_before(label,fragment,branch_targets=mode)
            m["code_hex"]=bytes(block.code).hex();m["document"]=block.update_document(m["document"])
        def hook(name,label,offset,fragment,mode="include"):
            by[name]["document"]["local_symbols"][label]=offset;insert(name,label,fragment,mode)
        def after_call(name,target,fragment,occurrence=-1):
            refs=[r for r in by[name]["document"]["references"] if r["kind"]=="call" and r["target"]==target]
            hook(name,name.lower()+".after."+target,refs[occurrence]["next_offset"],fragment)
        def add(name,rva,capacity,f,inputs,result,purpose,stack=False):
            d=copy.deepcopy(by["CombatReset"]["document"])
            d.update(name=name,contract_version=1,purpose=purpose,notes=[],tests=["--test","--smoke"])
            d["abi"].update(inputs=inputs,returns=result,memory_contracts=["Data.Upgrades","Data.Combat","Data.Board","Data.Frame"])
            d["implementation"].update(entry_rva=rva,implementation_rva=rva,slot_bytes=capacity,section=".mods",gate=None)
            d["implementation"].pop("unwind",None)
            m=dict(name=name,kind=1,capacity=8192,document=d);modules.append(m);by[name]=m;symbols[name]=rva
            return replace(name,f,stack=stack)

        # Reset the separate 256-byte upgrade context without touching neighboring data.
        f=B("pickupreset");f.e("49 89 ca 31 c0");f.l("clear")
        f.e("41 c6 04 02 00 ff c0 3d 00 01 00 00");f.j("0f 82","clear")
        f.e("41 c7 02 00 01 00 00 41 c7 42 04 01 00 00 00 41 c7 42 14 01 00 00 00 c3")
        add("PickupReset",0x20000,0x200,f,{"RCX":"Data.Upgrades*, writable 256 bytes"},"No result",
            "Reset run upgrades, four pickups and eight meteor damage masks.")

        # Hit only the first live geometric cell at the requested board coordinate.
        f=B("meteorhit");f.e("83 79 0c 00");f.j("0f 84","none")
        f.e("41 83 f8 32");f.j("0f 83","none");f.e("41 83 f9 10");f.j("0f 83","none")
        f.e("4c 8d 51 58 4c 8d 9a 80 00 00 00 48 81 c2 e0 00 00 00")
        f.l("meteor");f.e("41 83 7b 08 00");f.j("0f 84","next")
        for i,(dx,dy) in enumerate([(0,-1),(-1,0),(0,0),(1,0),(0,1)]):
            f.e("41 8b 03 41 8b 4b 04")
            if dx<0:f.e("ff c8")
            if dx>0:f.e("ff c0")
            if dy<0:f.e("ff c9")
            if dy>0:f.e("ff c1")
            f.e("44 39 c0");f.j("0f 85","cell"+str(i))
            f.e("44 39 c9");f.j("0f 85","cell"+str(i))
            f.e("41 f7 02");f.u(1<<i);f.j("0f 85","next")
            f.e("41 83 0a");f.e(bytes([1<<i]));f.e("41 83 3a 1f");f.j("0f 85","hit")
            f.e("41 c7 43 08 00 00 00 00");f.j("e9","hit");f.l("cell"+str(i))
        f.l("next");f.e("49 83 c3 0c 49 83 c2 04 49 39 d3");f.j("0f 82","meteor")
        f.l("none");f.e("31 c0 c3");f.l("hit");f.e("b8 01 00 00 00 c3")
        add("MeteorHit",0x20200,0x200,f,{"RCX":"Data.Upgrades*","RDX":"Data.Combat*",
            "R8D":"board x","R9D":"board y"},"EAX = one cell removed (1) or no change (0)",
            "Powered hits remove one live cross cell. Retire the entity only when all five bits are removed.")

        # Collect one item exactly at the player coordinate; shorten but never postpone a shot deadline.
        f=B("pickupcollect");f.e("49 89 ca 49 89 d3 44 89 c1 81 e1 ff ff 00 00 41 c1 e8 10 49 8d 52 18 b8 04 00 00 00")
        f.l("scan");f.e("83 7a 0c 00");f.j("0f 84","next")
        f.e("39 0a");f.j("0f 85","next");f.e("44 39 42 04");f.j("0f 85","next")
        f.e("83 7a 08 01");f.j("0f 84","fast");f.e("83 7a 08 02");f.j("0f 85","next")
        f.e("41 c7 42 0c 01 00 00 00");f.j("e9","consume")
        f.l("fast");f.e("41 83 7a 08 00");f.j("0f 85","consume")
        f.e("41 c7 42 08 01 00 00 00 41 8d 81 e8 03 00 00 41 39 43 08")
        f.j("0f 86","consume");f.e("41 89 43 08")
        f.l("consume");f.e("c7 42 0c 00 00 00 00 b8 01 00 00 00 c3")
        f.l("next");f.e("48 83 c2 10 ff c8");f.j("0f 85","scan");f.e("31 c0 c3")
        add("PickupCollect",0x20400,0x200,f,{"RCX":"Data.Upgrades*","RDX":"Data.Combat*",
            "R8D":"player x in low 16 bits, y in high 16 bits","R9D":"survival ms"},"EAX = collected (1) or none (0)",
            "Consume a matching F/P item. Upgrades persist until restart; repeated pickups do not stack.")

        f=B("pickupfall");f.e("48 83 ec 38 48 89 4c 24 20 4c 8d 51 18 41 b9 04 00 00 00")
        f.l("move");f.e("41 83 7a 0c 00");f.j("0f 84","next")
        f.e("41 ff 42 04 41 83 7a 04 10");f.j("0f 82","next")
        f.e("41 c7 42 0c 00 00 00 00");f.l("next");f.e("49 83 c2 10 41 ff c9");f.j("0f 85","move")
        f.e("ff 41 10 83 79 10 06");f.j("0f 82","done")
        f.e("c7 41 10 00 00 00 00 4c 8d 51 18 41 b9 04 00 00 00")
        f.l("free");f.e("41 83 7a 0c 00");f.j("0f 84","spawn")
        f.e("49 83 c2 10 41 ff c9");f.j("0f 85","free");f.j("e9","done")
        f.l("spawn");f.e("4c 89 54 24 28");f.call("Random")
        f.e("31 d2 b9 32 00 00 00 f7 f1 4c 8b 54 24 28 48 8b 4c 24 20 41 89 12 41 c7 42 04 00 00 00 00")
        f.e("8b 41 14 41 89 42 08 41 c7 42 0c 01 00 00 00 83 f0 03 89 41 14")
        f.l("done");f.e("48 83 c4 38 c3")
        add("PickupFall",0x20600,0x400,f,{"RCX":"Data.Upgrades*"},"No result",
            "Move bounded pickups once per fall and spawn alternating F/P every six falls when a slot is free.",True)

        f=B("pickupdraw");f.e("49 89 ca")
        for text,col,flag in [("FAST:OFF",28,8),("POWER:OFF",40,12)]:
            for i,ch in enumerate(text):
                f.e("c7 82");f.u((2*64+col+i)*4);f.u(0x00070000|ord(ch))
            f.e("41 83 7a");f.e(bytes([flag]));f.e("00");f.j("0f 84","hud"+str(flag))
            colon=text.index(":")
            for i,ch in enumerate(" ON"):
                f.e("c7 82");f.u((2*64+col+colon+1+i)*4);f.u((0x0a if flag==8 else 0x0d)<<16|ord(ch))
            f.l("hud"+str(flag))
        f.e("49 83 c2 18 b9 04 00 00 00")
        f.l("item");f.e("41 83 7a 0c 00");f.j("0f 84","next")
        f.e("41 8b 02 83 f8 32");f.j("0f 83","next")
        f.e("45 8b 5a 04 41 83 fb 10");f.j("0f 83","next")
        f.e("45 6b db 32 41 01 c3 43 80 bc 18 e0 00 00 00 00");f.j("0f 85","next")
        f.e("43 80 3c 19 00");f.j("0f 85","next")
        f.e("45 8b 5a 04 41 83 c3 04 41 c1 e3 06 41 01 c3 41 83 c3 07")
        f.e("41 83 7a 08 01");f.j("0f 85","power")
        f.e("42 c7 04 9a 46 00 0a 00");f.j("e9","next")
        f.l("power");f.e("41 83 7a 08 02");f.j("0f 85","next");f.e("42 c7 04 9a 50 00 0d 00")
        f.l("next");f.e("49 83 c2 10 ff c9");f.j("0f 85","item");f.e("c3")
        add("PickupDraw",0x20a00,0x400,f,{"RCX":"Data.Upgrades*","RDX":"Data.Frame*",
            "R8":"Data.Combat*","R9":"Data.Board*"},"No result",
            "Show upgrade HUD and clipped colored F/P items; occupied obstacle cells conceal items.")

        # Rebuild meteor occupancy from surviving cells; entity centers stay unchanged.
        f=B("meteormap");f.e("49 89 ca 4d 8d 9a e0 00 00 00 31 c0")
        f.l("clear");f.e("41 c6 04 03 00 ff c0 3d 20 03 00 00");f.j("0f 82","clear")
        f.e("4d 8d 82 80 00 00 00 41 b9 08 00 00 00");f.r("4c 8d 15","upgrades.damage")
        f.l("meteor");f.e("41 83 78 08 00");f.j("0f 84","next")
        for i,(dx,dy) in enumerate([(0,-1),(-1,0),(0,0),(1,0),(0,1)]):
            f.e("b8 08 00 00 00 44 29 c8 41 f7 04 82");f.u(1<<i);f.j("0f 85","skip"+str(i))
            f.e("41 8b 08 41 8b 50 04")
            if dx<0:f.e("ff c9")
            if dx>0:f.e("ff c1")
            if dy<0:f.e("ff ca")
            if dy>0:f.e("ff c2")
            f.e("83 f9 32");f.j("0f 83","skip"+str(i));f.e("83 fa 10");f.j("0f 83","skip"+str(i))
            f.e("6b c2 32 01 c8 41 c6 04 03 01");f.l("skip"+str(i))
        f.l("next");f.e("49 83 c0 0c 41 ff c9");f.j("0f 85","meteor");f.e("c3")
        replace("MeteorMap",f,"Rasterize only the remaining five-cell cross geometry, clipping every board write.")
        f=B("meteorfall.resetdamage");f.e("4c 8b 54 24 20 4c 89 c0 4c 29 d0 48 2d 80 00 00 00 31 d2 b9 0c 00 00 00 f7 f1")
        f.r("4c 8d 15","upgrades.damage");f.e("41 c7 04 82 00 00 00 00")
        insert("MeteorFall","meteorfall.map",f,"skip")

        f=B("tryfire");f.e("3b 51 08");f.j("0f 82","no")
        f.e("41 83 f8 32");f.j("0f 83","no");f.e("41 83 f9 01");f.j("0f 82","no")
        f.e("41 83 f9 10");f.j("0f 83","no")
        f.e("4c 8d 51 20 b8 08 00 00 00")
        f.l("free");f.e("41 83 7a 08 00");f.j("0f 84","fire")
        f.e("49 83 c2 0c ff c8");f.j("0f 85","free")
        f.l("no");f.e("31 c0 c3")
        f.l("fire");f.e("45 89 02 41 ff c9 45 89 4a 04 41 c7 42 08 01 00 00 00 b8 88 13 00 00")
        f.r("83 3d","upgrades.fast","00");f.j("0f 84","deadline");f.e("b8 e8 03 00 00")
        f.l("deadline");f.e("01 c2 89 51 08 ff 41 14 b8 01 00 00 00 c3")
        replace("TryFire",f,"Allocate a shot if ready; F changes successful-shot cooldown from 5000 to 1000 ms.")

        f=B("projectile");f.e("48 83 ec 38 48 89 4c 24 20 4c 89 44 24 28 49 89 ca 4d 89 c3")
        f.e("41 c7 42 18 00 00 00 00 89 d0 41 2b 42 0c 83 f8 64");f.j("0f 82","setup")
        f.e("41 89 52 0c 41 c7 42 18 01 00 00 00")
        f.l("setup");f.e("4d 8d 42 20")
        f.l("shot");f.e("41 83 78 08 00");f.j("0f 84","next")
        f.e("41 8b 08 41 8b 50 04 83 f9 32");f.j("0f 83","remove")
        f.e("83 fa 10");f.j("0f 83","remove");f.e("6b c2 32 01 c8 41 80 bc 02 e0 00 00 00 00")
        f.j("0f 85","meteor");f.e("41 80 3c 03 00");f.j("0f 85","star")
        f.e("41 83 7a 18 00");f.j("0f 84","next")
        f.e("41 ff 48 04 41 8b 50 04 83 fa 10");f.j("0f 83","remove")
        f.e("6b c2 32 01 c8 41 80 bc 02 e0 00 00 00 00");f.j("0f 85","meteor")
        f.e("41 80 3c 03 00");f.j("0f 85","star");f.j("e9","next")
        f.l("star");f.e("41 c6 04 03 00");f.j("e9","remove")
        f.l("meteor");f.e("4c 89 44 24 30 45 8b 48 04 45 8b 00 4c 89 d2")
        f.r("48 8d 0d","upgrades");f.call("MeteorHit");f.e("48 8b 4c 24 20");f.call("MeteorMap")
        f.e("4c 8b 54 24 20 4c 8b 5c 24 28 4c 8b 44 24 30")
        f.l("remove");f.e("41 c7 40 08 00 00 00 00")
        f.l("next");f.e("49 83 c0 0c 49 8d 82 80 00 00 00 49 39 c0");f.j("0f 82","shot")
        f.e("48 83 c4 38 c3")
        replace("ProjectileStep",f,"Advance dots at 100 ms cadence. Each dot removes one star or one powered meteor cell and is consumed.",True)

        f=B("reset.pickups");f.r("48 8d 0d","upgrades");f.call("PickupReset")
        hook("Reset","reset.pickups",len(bytes.fromhex(by["Reset"]["code_hex"]))-5,f)

        def collect_fragment(prefix):
            f=B(prefix);f.r("48 8d 0d","upgrades");f.r("48 8d 15","combat")
            f.r("44 8b 05","playerY");f.e("41 c1 e0 10");f.r("44 0b 05","playerX")
            f.r("44 8b 0d","elapsed");f.call("PickupCollect");return f
        insert("Tick","tick.collision",collect_fragment("tick.pickup.collect"))
        f=B("tick.pickup.fall");f.r("48 8d 0d","upgrades");f.call("PickupFall")
        c=collect_fragment("tick.pickup.afterfall")
        # Concatenate explicit blocks while preserving declared field origins.
        start=len(f.code);manifest=c.manifest();f.code.extend(c.code)
        f.references.extend(dict(r,offset=r["offset"]+start,next_offset=r["next_offset"]+start) for r in manifest["references"])
        after_call("Tick","MeteorFall",f)
        f=B("frame.pickup.draw");f.r("48 8d 0d","upgrades");f.r("48 8d 15","frame")
        f.r("4c 8d 05","combat");f.r("4c 8d 0d","board");f.call("PickupDraw")
        after_call("BuildFrame","CombatDraw",f)

        # Native assertions exercise the same byte functions used by the game.
        added=[];tests=B("pickup.tests")
        def call(name):tests.call(name)
        def ptr(prefix,target):tests.r(prefix,target)
        def read(name):ptr("8b 05",name)
        def setv(name,value):tests.r("c7 05",name,struct.pack("<I",value&0xffffffff))
        def alias(prefix,offset):
            name=prefix+"."+str(offset)
            if name not in symbols:symbols[name]=symbols[prefix]+offset
            return name
        def up(offset):return alias("upgrades",offset)
        def combat(offset):return alias("combat",offset)
        def setu(offset,value):setv(up(offset),value)
        def setc(offset,value):setv(combat(offset),value)
        def check(label,expected):
            name="pickup.test."+str(len(added));string(name,label);added.append(label)
            tests.e("ba");tests.u(expected);ptr("48 8d 0d",name);call("Assert")
        def reset():call("Reset")
        def collect(x=25,y=14,now=0):
            ptr("48 8d 0d","upgrades");ptr("48 8d 15","combat")
            tests.e("41 b8");tests.u(x|(y<<16));tests.e("41 b9");tests.u(now);call("PickupCollect")
        def item(slot,x,y,kind=1):
            at=24+slot*16
            for offset,val in [(0,x),(4,y),(8,kind),(12,1)]:setu(at+offset,val)
        def meteor(slot=0,x=10,y=5):
            for offset,val in [(0,x),(4,y),(8,1)]:setc(128+slot*12+offset,val)
        def shot(x=10,y=5):
            for offset,val in [(0,x),(4,y),(8,1)]:setc(32+offset,val)
        def cmap():ptr("48 8d 0d","combat");call("MeteorMap")
        def step(now=0):
            ptr("48 8d 0d","combat");tests.e("ba");tests.u(now);ptr("4c 8d 05","board");call("ProjectileStep")
        def fire(now):
            ptr("48 8d 0d","combat");tests.e("ba");tests.u(now);tests.e("41 b8 19 00 00 00 41 b9 0e 00 00 00");call("TryFire")
        def hit(x,y):
            ptr("48 8d 0d","upgrades");ptr("48 8d 15","combat")
            tests.e("41 b8");tests.u(x);tests.e("41 b9");tests.u(y);call("MeteorHit")
        def fall():ptr("48 8d 0d","upgrades");call("PickupFall")
        def readhaz(x,y):ptr("0f b6 05",combat(224+y*50+x))
        def readcell(x,y):ptr("8b 05",alias("frame",(64*(y+4)+x+7)*4))
        reset();setv("upgrades.guard",0x6a5b4c3d)
        read(up(0));check("pickup context bounded size",256)
        read(up(4));check("pickup ABI initialized",1)
        read(up(20));check("first pickup is F",1)
        read(up(8));check("F cleared on restart",0)
        read(up(12));check("P cleared on restart",0)
        read(up(88));check("damage cleared on restart",0)
        item(0,25,14);collect();check("collect F at player",1)
        read(up(8));check("F enables fast shooting",1)
        read(up(36));check("collected F removed",0)
        fire(0);check("F immediate shot",1)
        read(combat(8));check("F cooldown is one second",1000)
        fire(999);check("F respects 999 ms deadline",0)
        fire(1000);check("F accepts 1000 ms shot",1)
        reset();fire(0);item(0,25,14);collect(now=2000)
        read(combat(8));check("F shortens pending cooldown",3000)
        item(0,25,14);collect(now=2100);read(combat(8));check("repeated F does not delay deadline",3000)
        reset();item(0,24,14);collect();check("adjacent pickup not collected",0)
        item(1,25,14,2);collect();check("collect P at player",1)
        read(up(12));check("P enables cell damage",1)
        read(up(8));check("P alone keeps slow cooldown",0)
        reset();setu(12,1);meteor();cmap();shot();step()
        read(up(88));check("powered dot removes center only",4)
        read(combat(136));check("partial meteor remains active",1)
        read(combat(40));check("powered dot consumed after one cell",0)
        readhaz(10,5);check("removed center no longer collides",0)
        readhaz(9,5);check("neighbor meteor cell still solid",1)
        cmap();read(up(88));check("map rebuild preserves damage",4)
        hit(10,5);check("already removed cell cannot be hit twice",0)
        hit(9,4);check("empty cross corner cannot be damaged",0)
        ptr("48 8d 0d","combat");call("MeteorFall")
        read(up(88));check("fall preserves meteor damage",4)
        readhaz(10,6);check("damaged hole follows falling meteor",0)
        setv("playerX",10);setv("playerY",6);call("Collision");check("player safe in damaged hole",0)
        setv("playerX",9);call("Collision");check("remaining meteor cell collides",1)
        reset();setu(12,1);meteor();cmap()
        for x,y in [(10,4),(9,5),(10,5),(11,5),(10,6)]:shot(x,y);step()
        read(up(88));check("five dots remove five cells",31)
        read(combat(136));check("cleared meteor retires",0)
        readhaz(10,6);check("cleared meteor has no hazards",0)
        reset();setu(12,1);meteor();meteor(1);cmap();shot();step()
        read(up(88));check("overlap damages first meteor once",4)
        read(up(92));check("one dot does not pierce overlapping meteor",0)
        reset();setu(12,1);meteor();cmap()
        star=alias("board",5*50+10);tests.r("c6 05",star,"01");shot();step()
        ptr("0f b6 05",star);check("meteor hit does not pierce into star",1)
        shot();step();ptr("0f b6 05",star);check("second dot passes hole and destroys star",0)
        reset();setu(88,31);setc(16,9);ptr("48 8d 0d","combat");call("MeteorFall")
        read(up(88));check("respawned meteor restores its cells",0)
        reset()
        for _ in range(5):fall()
        read(up(36));check("no pickup before sixth fall",0)
        fall();read(up(36));check("sixth fall spawns pickup",1)
        read(up(32));check("first spawn is F",1)
        read(up(28));check("pickup spawn starts at top",0)
        read(up(24));tests.e("83 f8 32 0f 92 c0 0f b6 c0");check("pickup spawn x is bounded",1)
        fall();read(up(28));check("pickup falls with board",1)
        for _ in range(5):fall()
        read(up(48));check("next spawn is P",2)
        setu(28,15);fall();read(up(36));check("pickup retires below board",0)
        reset()
        for i in range(4):item(i,10+i,1,1 if i%2==0 else 2)
        setu(16,5);fall();read(up(32));check("full pickup pool not overwritten",1)
        read(up(20));check("failed spawn does not toggle item type",1)
        reset();item(0,10,5);item(1,11,5,2);call("BuildFrame")
        readcell(10,5);check("F rendered as green pickup",0x000a0046)
        readcell(11,5);check("P rendered as magenta pickup",0x000d0050)
        meteor();cmap();call("BuildFrame");readcell(10,5);check("meteor conceals overlapping pickup",0x000c0023)
        reset();item(0,10,5);tests.r("c6 05",star,"01");call("BuildFrame")
        readcell(10,5);check("star conceals overlapping pickup",0x000e002a)
        reset();item(0,25,14,2);collect();setu(88,4);reset()
        read(up(12));check("restart removes power upgrade",0)
        read(up(88));check("restart removes meteor damage",0)
        read(up(36));check("restart clears all pickups",0)
        read("upgrades.guard");check("pickup context guard intact",0x6a5b4c3d)
        refs=[r for r in by["CombatTests"]["document"]["references"] if r["target"]=="Reset" and r["kind"]=="call"]
        hook("CombatTests","combattests.pickups",refs[-1]["next_offset"]-5,tests)
        by["CombatTests"]["document"]["notes"]+=added

        unit_added=len(added)
        smoke_checks=[];tests=B("pickup.smoke")
        def smokecheck(label,expected):
            name="pickup.smoke."+str(len(smoke_checks));string(name,label);smoke_checks.append(label)
            tests.e("ba");tests.u(expected);ptr("48 8d 0d",name);call("Assert")
        item(0,25,14,1);item(1,25,14,2);setv("input",64);call("Tick");call("Tick")
        read(up(8));smokecheck("game loop collects F pickup",1)
        read(up(12));smokecheck("game loop collects P pickup",1)
        # Check actual deadline relative to elapsed rather than assuming OS timer precision.
        read(combat(8));ptr("2b 05","elapsed");tests.e("3d e8 03 00 00 0f 96 c0 0f b6 c0")
        smokecheck("game loop applies fast firing deadline",1)
        meteor();cmap();shot();step()
        read(up(88));smokecheck("game projectile removes one meteor cell",4)
        read(combat(136));smokecheck("game keeps partial meteor active",1)
        call("Start")
        after_call("Smoke","Start",tests)
        by["Smoke"]["document"]["notes"]+=smoke_checks

        contract=dict(schema="llm-pe.module.v1",name="Data.Upgrades",contract_version=1,
            purpose="Bounded per-run pickups and persistent five-cell meteor damage; separate from the unchanged input/combat ABI.",
            rva=0x18500,size=256,alignment=8,ownership="Single game thread; PickupReset at every new run.",
            fields=[
                dict(name="size_bytes",offset=0,type="uint32",value=256),
                dict(name="abi_major",offset=4,type="uint32",value=1),
                dict(name="fast_fire",offset=8,type="uint32",invariant="0 or 1"),
                dict(name="strong_shots",offset=12,type="uint32",invariant="0 or 1"),
                dict(name="pickup_fall_counter",offset=16,type="uint32",invariant="0..5"),
                dict(name="next_pickup_type",offset=20,type="uint32",invariant="1=F or 2=P"),
                dict(name="pickups",offset=24,type="Pickup[4]",element_size=16),
                dict(name="removed_cells",offset=88,type="uint32[8]",invariant="only low five bits set"),
                dict(name="reserved",offset=120,type="uint8[136]")],
            pickup_layout=dict(x=dict(offset=0,type="int32"),y=dict(offset=4,type="int32"),
                kind=dict(offset=8,type="uint32",invariant="1=F,2=P"),active=dict(offset=12,type="uint32",invariant="0 or 1")),
            damage_bits={"1":"top (0,-1)","2":"left (-1,0)","4":"center (0,0)","8":"right (1,0)","16":"bottom (0,1)"},
            invariants=["Damage mask index matches the combat meteor slot; MeteorMap clips and excludes removed cells.",
                "MeteorFall clears a mask only when reusing a free entity slot; ordinary movement retains damage.",
                "One powered projectile is consumed after removing one live cell, including overlapping entities.",
                "F changes cooldown to 1000 ms and shortens an existing later deadline; repeated pickups do not stack.",
                "P applies to all active projectiles; F and P persist until Reset.",
                "Pickups alternate F/P every six board falls, bounded to four slots; inactive slots may be reused.",
                "PickupCollect handles one coordinate match per call; obstacles hide pickups until the cell is free."],
            test_guard=dict(rva=0x18600,type="uint32",ownership="CombatTests only; outside context"),
            readers=["MeteorMap","MeteorHit","TryFire","PickupCollect","PickupFall","PickupDraw"],
            writers=["PickupReset","MeteorHit","MeteorFall","PickupCollect","PickupFall"])
        modules.insert(10,dict(name="Data.Upgrades",kind=2,capacity=8192,document=contract));by["Data.Upgrades"]=modules[10]
        combat_doc=by["Data.Combat"]["document"]
        combat_doc["related_contracts"]=["Data.Upgrades"]
        combat_doc["invariants"]=[v.replace("Shot cooldown 5000 ms;","Shot cooldown 5000 ms, or 1000 ms with F;") for v in combat_doc["invariants"]]
        combat_doc["invariants"].append("Damage geometry lives in Data.Upgrades; memory layout and abi_major=2 remain unchanged.")
        combat_doc["readers"]+=["MeteorHit","PickupDraw","PickupCollect"]
        combat_doc["writers"]+=["MeteorHit","PickupCollect"]
        frame_doc=by["Data.Frame"]["document"]
        frame_doc["colors"].update(fast_pickup=10,power_pickup=13)
        frame_doc["writers"].append("PickupDraw")
        frame_doc["contract_version"]=3
        testing=by["Data.Testing"]["document"]
        testing["native_unit_assertions"]=127+unit_added
        testing["coverage"].update(unit_count=127+unit_added,smoke_assertions=11+len(smoke_checks),smoke_frames=400)
        testing["contract_version"]=2
        architecture=by["Architecture"]["document"]
        architecture["contract_version"]=3
        architecture["purpose"]="Starfall with collectable firing upgrades and individually destructible meteor cells."
        architecture["gameplay"].update(fire="Space: 5000 ms cooldown, or 1000 ms with collected F",
            meteor="five # cross cells; normal dots absorbed; P removes exactly one live cell per dot",
            pickups="F: fast fire; P: power shots. Alternate every six falls; upgrades last until restart.")
        architecture["validation"]=dict(native_unit_assertions=127+unit_added,native_smoke_assertions=11+len(smoke_checks),native_smoke_frames=400)
        architecture["design"]["data"]="Stable legacy/input/combat RVAs plus separate bounded 256-byte Data.Upgrades context."
        architecture["migration"]="Explicit v4 pickup/data/module migration; every v3 public function entry and input ABI stays stable."
        for name,contracts in {
            "PickupReset":["Data.Upgrades"],
            "MeteorHit":["Data.Upgrades","Data.Combat"],
            "PickupCollect":["Data.Upgrades","Data.Combat"],
            "PickupFall":["Data.Upgrades","Data.State"],
            "PickupDraw":["Data.Upgrades","Data.Combat","Data.Board","Data.Frame"],
        }.items():by[name]["document"]["abi"]["memory_contracts"]=contracts
        architecture["modules"]=[m["name"] for m in modules if m["kind"]==1]
        architecture["module_count"]=len(modules)
        by["ProjectileStep"]["document"]["notes"]=[
            "Check current and next cells so falling objects cannot pass through stationary dots.",
            "Meteor occupancy has priority over overlapping stars. Each dot is consumed after a single hit.",
            "Powered hits call MeteorHit then rebuild MeteorMap immediately; restored stack locals survive volatile calls."]
        by["CombatDraw"]["document"]["purpose"]="Draw the current meteor hazard cells, cyan dots and the remaining shot-cooldown HUD."
        by["CombatDraw"]["document"]["contract_version"]=2
        by["Collision"]["document"]["purpose"]="Check the player cell for a star or a remaining meteor cell."
        by["Collision"]["document"]["abi"]["returns"]="EAX 1 for a live hazard, otherwise 0; destroyed meteor cells are safe."
        by["Collision"]["document"]["contract_version"]=3
        by["MeteorFall"]["document"]["notes"].append("Clear only the spawned/reused entity's damage mask; existing moving entities retain missing cells.")
        changed=["Reset","MeteorMap","MeteorFall","TryFire","ProjectileStep","Tick","BuildFrame","CombatTests","Smoke"]
        for name in changed:
            d=by[name]["document"];d["contract_version"]=d.get("contract_version",1)+1
            d["abi"]["memory_contracts"]=list(dict.fromkeys(d["abi"]["memory_contracts"]+["Data.Upgrades"]))
            d["notes"].append("Pickup v4 adds per-run upgrade state; working keyboard adapter bytes are unchanged.")
        by["MeteorMap"]["document"]["abi"]["inputs"]={"RCX":"Data.Combat*; reads the fixed Data.Upgrades damage table."}
        by["TryFire"]["document"]["abi"]["inputs"].update(RCX="Data.Combat*; reads fixed Data.Upgrades.fast_fire.")
        for m in modules:
            if m["kind"]!=1:continue
            d=m["document"];code=bytes.fromhex(m["code_hex"])
            if len(code)>d["implementation"]["slot_bytes"]:raise ValueError("Code slot exhausted: "+m["name"]+" "+str(len(code)))
            for name,offset in d["local_symbols"].items():symbols[name]=d["implementation"]["implementation_rva"]+offset
            refs=d["references"];d["dependencies"]=dict(
                functions=sorted({r["target"] for r in refs if r["kind"]=="call"}),
                imports=sorted({r["target"].removeprefix("iat.") for r in refs if r["kind"]=="import"}),
                memory_symbols=sorted({r["target"] for r in refs if r["kind"]=="rip"}),
                contracts=d["abi"]["memory_contracts"])
            m["capacity"]=max(m["capacity"],wb.align(len(wb.canonical(d))+4096,4096))
        for name,value in by["Data.Frame"]["document"].get("aliases",{}).items():
            if name in symbols:by["Data.Frame"]["document"]["aliases"][name]=symbols[name]
        by["Symbols"]["capacity"]=max(by["Symbols"]["capacity"],wb.align(len(wb.canonical(by["Symbols"]["document"]))+4096,4096))
        needed=spec["metadata"]["arena_offset"]+sum(m["capacity"] for m in modules)
        metadata_size=max(spec["metadata"]["raw_size"],wb.align(needed+0x4000,0x10000))
        spec["metadata"].update(raw_size=metadata_size,virtual_size=metadata_size,format="concise-v1")
        architecture["design"]["growth"]["metadata_bytes"]=metadata_size
        architecture["reserve_profile"]["metadata_bytes"]=metadata_size
        base_path=arch/"pickup-base.exe";base_path.write_bytes(base)
        spec["base_file"]="architecture/pickup-base.exe";spec["output_file"]="Starfall.exe"
        spec_path=arch/"migration.json";spec_path.write_bytes(wb.canonical(spec));wb.migrate(spec_path,out/"Starfall.exe")
        with wb.PE(out/"Starfall.exe",metadata=False) as emitted:
            actual_metadata_size=emitted.section(".llm")["raw_size"]
        print(json.dumps(dict(unit_assertions=127+unit_added,smoke_assertions=11+len(smoke_checks),
            output=str(out/"Starfall.exe"),metadata_size=actual_metadata_size,
            functions={m["name"]:len(bytes.fromhex(m["code_hex"])) for m in modules if m["kind"]==1 and m["name"] in changed+["PickupReset","MeteorHit","PickupCollect","PickupFall","PickupDraw"]}),indent=2))

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workbench",required=True);parser.add_argument("--source",required=True);parser.add_argument("--directory",required=True)
    build(parser.parse_args())
