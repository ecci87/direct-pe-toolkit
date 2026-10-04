#!/usr/bin/env python3
"""Integration checks for the raw-byte maintenance protocol, including real native tests."""
import copy
import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
import atexit
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT/".agents/skills/direct-pe-x64/scripts/pe_workbench.py"
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--fixture",type=Path,default=ROOT/"examples/starfall/Starfall.exe")
parser.add_argument("--migration",type=Path,default=ROOT/"examples/starfall/architecture/migration.json")
args=parser.parse_args()
FIXTURE=args.fixture.resolve()
MIGRATION=args.migration.resolve()
if os.name != "nt":
    raise SystemExit("Native integration checks require Windows x64; inspect/verify can run elsewhere.")
WORK=ROOT/"out"/"work";WORK.mkdir(parents=True,exist_ok=True)
OUT=Path(tempfile.mkdtemp(prefix="maintenance-",dir=WORK))
def retain_evidence():
    report=OUT/"report.json"
    if report.exists():
        evidence=ROOT/"out"/"evidence";evidence.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(report,evidence/"maintenance.json")
        if OUT.resolve().parent!=WORK.resolve() or not OUT.resolve().is_relative_to((ROOT/"out").absolute()) or OUT.is_symlink():raise RuntimeError("Unsafe test workspace")
        shutil.rmtree(OUT)
atexit.register(retain_evidence)
EXE = OUT/"Starfall.exe"
shutil.copyfile(FIXTURE,EXE)
fixture_hash = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
print("Evidence directory: "+str(OUT),flush=True)
spec = importlib.util.spec_from_file_location("wb",TOOL)
wb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wb)
results=[]

def check(name, condition):
    if not condition:
        raise AssertionError(name)
    results.append(dict(test=name,pass_=True))
    print("PASS  "+name,flush=True)

def cli(*args, success=True):
    p=subprocess.run([sys.executable,str(TOOL),*map(str,args)],capture_output=True,text=True,timeout=30)
    if success and p.returncode!=0:
        raise AssertionError(p.stderr+p.stdout)
    if not success and p.returncode==0:
        raise AssertionError("Expected rejected operation: "+repr(args))
    return p

def native(exe,*args,console=False,expected=0):
    startup=None
    flags=0
    if os.name=="nt":
        startup=subprocess.STARTUPINFO()
        startup.dwFlags=subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow=0
        flags=subprocess.CREATE_NEW_CONSOLE if console else subprocess.CREATE_NO_WINDOW
    p=subprocess.run([str(exe),*args],cwd=str(exe.parent),capture_output=True,timeout=30,
                     startupinfo=startup,creationflags=flags)
    if p.returncode!=expected:
        raise AssertionError("Native exit "+str(p.returncode)+": "+p.stderr.decode(errors="replace")+p.stdout.decode(errors="replace"))
    return p

with wb.PE(EXE) as pe:
    function_hashes={r["name"]:r["code_hash"] for r in pe.records if r["kind"]==1}
    doc_hashes={r["name"]:(r["doc_hash"],wb.digest(wb._meta.compact(pe.technical(r)))) for r in pe.records}
    move=pe.record("Move")
    move_doc=pe.document(move)
    move_brief=pe.brief(move)
    move_code=pe.code(move)
    arch=pe.document(pe.record("Architecture"))
    legacy_entry=move["entry"]
UNIT=arch.get("validation",{}).get("native_unit_assertions",51)
SMOKE=arch.get("validation",{}).get("native_smoke_assertions",5)
inspect=json.loads(cli("inspect",EXE,"Move","--bytes").stdout)
check("selective inspection reads under one tenth of image",inspect["read_stats"]["bytes_read"]<EXE.stat().st_size//10)
check("selective inspection contains only Move document",inspect["module"]["name"]=="Move" and len(inspect["code_hex"])==154)
check("inspection reports exact remaining document reserve",
      inspect["storage"]["document_free_bytes"]==wb.metadata_free(move))
check("native self-description matches embedded module",json.loads(native(EXE,"--describe","Move").stdout)==move_brief)
check("native default description prints Architecture",json.loads(native(EXE,"--describe").stdout)["name"]=="Architecture")
check("native data contract description",json.loads(native(EXE,"--describe","Data.ScoreRecord").stdout)["size"]==16)
check("unknown native module returns exit 2",b"Unknown embedded module" in native(EXE,"--describe","missing",expected=2).stdout)
p=native(EXE,"--test")
check("updated EXE passes its declared native unit assertions",p.stdout.count(b"PASS  ")==UNIT and b"ALL TESTS PASSED" in p.stdout)
p=native(EXE,"--smoke",console=True)
check("updated EXE passes its declared console assertions",p.stdout.count(b"PASS  ")==SMOKE)
cli("patch-template",EXE,"Move","--output",OUT/"move.patch.json")
patch=json.loads((OUT/"move.patch.json").read_text())
check("patch template exposes document and code capacities",
      patch["limits"]["document_capacity_bytes"]==move["doc_capacity"] and patch["limits"]["code_slot_bytes"]==move["slot"])
too_large=copy.deepcopy(patch)
too_large["documentation"]["purpose"]="x"*move["doc_capacity"]
(OUT/"too-large-document.patch.json").write_bytes(wb.canonical(too_large))
cli("patch",EXE,OUT/"too-large-document.patch.json","--output",OUT/"too-large-document.exe",success=False)
check("document overflow leaves no promoted or temporary candidate",
      not (OUT/"too-large-document.exe").exists() and not (OUT/"too-large-document.exe.building").exists())
patch["reason"]="Maintenance test: insert one NOP before RET; movement semantics remain unchanged."
patch["hex"]=(move_code[:-1]+b"\x90\xc3").hex()
(OUT/"move.patch.json").write_bytes(wb.canonical(patch))
cli("patch",EXE,OUT/"move.patch.json","--output",OUT/"one-function.exe")
with wb.PE(OUT/"one-function.exe") as pe:
    after={r["name"]:r["code_hash"] for r in pe.records if r["kind"]==1}
    docs_after={r["name"]:(r["doc_hash"],wb.digest(wb._meta.compact(pe.technical(r)))) for r in pe.records}
    check("same-slot patch changes only Move code hash",[n for n in function_hashes if after[n]!=function_hashes[n]]==["Move"])
    check("same-slot patch changes only Move metadata",[n for n in doc_hashes if docs_after[n]!=doc_hashes[n]]==["Move"])
    check("same-slot patch preserves public address",pe.record("Move")["entry"]==legacy_entry)
    patched_move=pe.record("Move")
    allowed=[(pe.offset(patched_move["impl"],patched_move["slot"]),pe.offset(patched_move["impl"],patched_move["slot"])+patched_move["slot"]),
             (pe.offset(patched_move["doc_rva"],patched_move["doc_capacity"]),pe.offset(patched_move["doc_rva"],patched_move["doc_capacity"])+patched_move["doc_capacity"]),
             (patched_move["record_offset"],patched_move["record_offset"]+wb.RECORD_SIZE),
             (pe.section(".pdata")["raw_offset"],pe.section(".pdata")["raw_offset"]+pe.section(".pdata")["raw_size"])]
    report=json.loads(Path(str(OUT/"one-function.exe")+".patch-report.json").read_text())
    check("byte diff is limited to function, its metadata and unwind",[r for r in report["ranges"] if not any(a<=r[0] and r[1]<=b for a,b in allowed)]==[])
p=native(OUT/"one-function.exe","--test")
check("same-slot patch still passes all native tests",p.stdout.count(b"PASS  ")==UNIT)
cli("patch",OUT/"one-function.exe",OUT/"move.patch.json","--output",OUT/"stale.exe",success=False)
check("stale patch rejected before candidate creation",not (OUT/"stale.exe").exists())
bad=copy.deepcopy(patch)
bad["documentation"]["abi"]["inputs"]["ECX"]="uint64 incompatible input"
(OUT/"bad-abi.patch.json").write_bytes(wb.canonical(bad))
cli("patch",EXE,OUT/"bad-abi.patch.json","--output",OUT/"bad-abi.exe",success=False)
check("ABI-breaking patch rejected",not (OUT/"bad-abi.exe").exists())
oversize=copy.deepcopy(patch)
oversize["reason"]="Maintenance test: oversized equivalent Move body to exercise stable jump gate."
oversize["hex"]=(move_code[:-1]+b"\x90"*(1100-len(move_code))+b"\xc3").hex()
(OUT/"oversize.patch.json").write_bytes(wb.canonical(oversize))
cli("patch",EXE,OUT/"oversize.patch.json","--output",OUT/"overflow-rejected.exe",success=False)
check("overflow requires explicit relocation",not (OUT/"overflow-rejected.exe").exists())
cli("patch",EXE,OUT/"oversize.patch.json","--output",OUT/"relocated.exe","--relocate")
with wb.PE(OUT/"relocated.exe") as pe:
    r=pe.record("Move")
    d=pe.document(r)
    check("relocation keeps original callable entry",r["entry"]==legacy_entry and r["impl"]!=legacy_entry)
    check("relocation has explicit jump gate and separate unwind",d["implementation"]["gate"]["used_bytes"]==5 and d["implementation"]["gate"]["unwind"]["begin_rva"]==legacy_entry)
    check("relocation changes no other function implementation hash",all(r["name"]=="Move" or r["code_hash"]==function_hashes[r["name"]] for r in pe.records if r["kind"]==1))
    check("global symbol registry remains stable after relocation",pe.document(pe.record("Symbols"))["symbols"]["Move"]==legacy_entry)
p=native(OUT/"relocated.exe","--test")
check("relocated raw-byte function passes all native assertions",p.stdout.count(b"PASS  ")==UNIT)
p=native(OUT/"relocated.exe","--smoke",console=True)
check("relocated function passes real console integration",p.stdout.count(b"PASS  ")==SMOKE)
cli("export",EXE,OUT/"project")
cli("build",OUT/"project","--output",OUT/"rebuilt.exe")
check("deterministic project rebuild is byte-for-byte identical",wb.stream_hash(EXE)==wb.stream_hash(OUT/"rebuilt.exe"))
shutil.copyfile(EXE,OUT/"corrupted.exe")
with open(OUT/"corrupted.exe","r+b") as f,wb.PE(EXE) as pe:
    at=pe.offset(pe.record("Move")["impl"])
    f.seek(at)
    value=f.read(1)
    f.seek(at)
    f.write(bytes([value[0]^1]))
cli("verify",OUT/"corrupted.exe",success=False)
check("corrupted code is detected by embedded hash",True)
# Add a Unicode/spaces scenario for new native metadata and file APIs.
unicode_dir=OUT/"path with spaces - \u661f"
unicode_dir.mkdir()
shutil.copyfile(EXE,unicode_dir/"Starfall.exe")
check("native description works from Unicode/spaced path",json.loads(native(unicode_dir/"Starfall.exe","--describe","Move").stdout)["name"]=="Move")
p=native(unicode_dir/"Starfall.exe","--test")
check("native tests work from Unicode/spaced path",p.stdout.count(b"PASS  ")==UNIT)

# Exercise append-only growth twice, using the existing stable entry.
cli("patch-template",OUT/"relocated.exe","Move","--output",OUT/"second-growth.patch.json")
growth=json.loads((OUT/"second-growth.patch.json").read_text())
growth["reason"]="Maintenance check: second equivalent body growth preserves the gate."
growth["hex"]=(move_code[:-1]+b"\x90"*(2300-len(move_code))+b"\xc3").hex()
(OUT/"second-growth.patch.json").write_bytes(wb.canonical(growth))
cli("patch",OUT/"relocated.exe",OUT/"second-growth.patch.json","--output",OUT/"second-growth.exe","--relocate")
with wb.PE(OUT/"second-growth.exe") as pe:
    grown=pe.record("Move")
    grown_doc=pe.document(grown)
    check("second growth preserves entry and retires previous body",
          grown["entry"]==legacy_entry and len(grown_doc["implementation"]["retired"])==1)
p=native(OUT/"second-growth.exe","--test")
check("twice relocated body passes all native assertions",p.stdout.count(b"PASS  ")==UNIT)

# A deliberately incorrect expected value must make the native test runner fail.
# This raw offset is pinned to the checked-in v1-derived fixture's Tests slot.
shutil.copyfile(EXE,OUT/"intentional-assertion-failure.exe")
with open(OUT/"intentional-assertion-failure.exe","r+b") as f:
    f.seek(0x649a)
    expected_byte=f.read(1)
    f.seek(0x649a)
    f.write(bytes([expected_byte[0]^1]))
p=native(OUT/"intentional-assertion-failure.exe","--test",expected=1)
check("native failed assertion produces FAIL log and exit 1",b"FAIL" in p.stdout)

# Generic new builds only an exit scaffold; do not mistake it for an app/test runner.
cli("new","--output",OUT/"scaffold.exe")
scaffold=json.loads(cli("inspect",OUT/"scaffold.exe","Architecture").stdout)["module"]
check("scaffold honestly declares missing native diagnostic modes",
      scaffold["native_modes"]==dict(test=False,smoke=False,describe=False))
native(OUT/"scaffold.exe")
check("raw-byte scaffold loads and exits on Windows",True)
cli("new","--output",OUT/"custom-imports.exe","--imports","KERNEL32.dll:ExitProcess","USER32.dll:GetAsyncKeyState")
cli("verify",OUT/"custom-imports.exe")
native(OUT/"custom-imports.exe")
check("explicit Windows DLL imports produce loader-valid scaffold",True)
cli("migrate",MIGRATION,"--output",OUT/"migration-rebuilt.exe")
check("raw migration reproduces annotated fixture byte-for-byte",
      wb.stream_hash(EXE)==wb.stream_hash(OUT/"migration-rebuilt.exe"))
check("test harness preserves checked-in fixture",
      hashlib.sha256(FIXTURE.read_bytes()).hexdigest()==fixture_hash)

(OUT/"report.json").write_bytes(wb.canonical(dict(passed=len(results),results=results,exe_sha256=wb.stream_hash(EXE))))
print("ALL "+str(len(results))+" MAINTENANCE CHECKS PASSED",flush=True)
