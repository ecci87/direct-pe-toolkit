#!/usr/bin/env python3
"""Application-neutral construction/context/import/static-analysis regressions."""
import argparse
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest
import uuid
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT/".agents/skills/direct-pe-x64/scripts/pe_workbench.py"
args, rest = argparse.ArgumentParser(add_help=False), None
args.add_argument("--analyzer-path")
options, rest = args.parse_known_args()
sys.argv = [sys.argv[0]]+rest
if options.analyzer_path:
    sys.path.insert(0, str(Path(options.analyzer_path).resolve()))
try:
    import capstone
except ImportError:
    capstone = None
spec = importlib.util.spec_from_file_location("wb", SCRIPT)
wb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wb)
raw = wb._raw
WORK = ROOT/"out"/"work"
WORK.mkdir(parents=True,exist_ok=True)
OUT = Path(tempfile.mkdtemp(prefix="primitives-",dir=WORK))
def silent(call, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()):
        return call(*args, **kwargs)

class ImportPackingTests(unittest.TestCase):
    def test_names_thunks_terminators_and_prefix(self):
        prefix = b"preserved section bytes"
        packed = raw.pack_imports(["KERNEL32.dll:ExitProcess", "ADVAPI32.dll:StartServiceCtrlDispatcherW"],
                                  0x11000, prefix=prefix)
        data = packed["data"]
        self.assertEqual(data[:len(prefix)], prefix)
        start, size = packed["import_directory"]
        self.assertEqual(data[start-0x11000+size-20:start-0x11000+size], b"\0"*20)
        for pos in range(start-0x11000, start-0x11000+size-20, 20):
            ilt, _, _, name, iat = struct.unpack_from("<5I", data, pos)
            self.assertEqual(ilt%8, 0)
            self.assertEqual(iat%8, 0)
            self.assertEqual(data[ilt-0x11000:ilt-0x11000+16], data[iat-0x11000:iat-0x11000+16])
            hint = struct.unpack_from("<Q", data, ilt-0x11000)[0]
            self.assertEqual(data[hint-0x11000:hint-0x11000+2], b"\0\0")
            self.assertTrue(data[hint-0x11000+2:hint-0x11000+3].isalpha())

    def test_malformed_and_embedded_terminators_rejected(self):
        for declaration in ["kernel32:ExitProcess", "KERNEL32.dll:0ExitProcess", "KERNEL32.dll:ExitProcess\0",
                            r"KERNEL32.dll:ExitProcess\0"]:
            with self.assertRaises(ValueError):
                raw.pack_imports([declaration], 0x11000)

    def test_capacity_and_casefolded_duplicate(self):
        with self.assertRaises(ValueError):
            raw.pack_imports(["KERNEL32.dll:ExitProcess"], 0x11000, capacity=8)
        packed = raw.pack_imports(["KERNEL32.dll:ExitProcess", "kernel32.dll:ExitProcess"], 0x11000)
        self.assertEqual(len(packed["entries"]), 1)
        self.assertEqual(len(packed["entries"][0]["functions"]), 1)

    def test_ambiguous_exports_require_qualified_symbols(self):
        packed = raw.pack_imports(["FIRST.dll:SameName", "SECOND.dll:SameName"], 0x11000)
        self.assertNotIn("iat.SameName", packed["symbols"])
        self.assertIn("iat.FIRST.dll.SameName", packed["symbols"])

class ByteEditingTests(unittest.TestCase):
    def make(self):
        return raw.ByteBlock().relative("e9", "fn.return", kind="branch").label("fn.return").emit("c3")

    def test_include_and_skip_have_distinct_branch_destinations(self):
        for policy, expected in [("include", 5), ("skip", 6)]:
            block = self.make().insert_before("fn.return", raw.ByteBlock().emit("90"), branch_targets=policy)
            manifest = block.manifest()
            self.assertEqual(manifest["references"][0]["local"], expected)
            resolved = wb.patch_references(manifest, bytes(block.code), {}, 0x1000)
            self.assertEqual(0x1000+5+struct.unpack_from("<i", resolved, 1)[0], 0x1000+expected)

    def test_full_instruction_end_includes_immediate_tail(self):
        block = raw.ByteBlock().relative("c7 05", "output", "78563412").emit("c3")
        doc = block.manifest()
        code = wb.patch_references(doc, bytes(block.code), {"output":0x5000}, 0x1000)
        self.assertEqual(doc["references"][0]["next_offset"], 10)
        self.assertEqual(struct.unpack_from("<i", code, 2)[0], 0x5000-(0x1000+10))

    def test_label_collision_is_atomic(self):
        block = self.make()
        before = block.manifest()
        with self.assertRaises(ValueError):
            block.insert_before("fn.return", raw.ByteBlock().label("fn.return").emit("90"), branch_targets="include")
        self.assertEqual(block.manifest(), before)

    def test_overlapping_fields_and_stale_label_rejected(self):
        doc = self.make().manifest()
        doc["references"].append(copy.deepcopy(doc["references"][0]))
        with self.assertRaises(ValueError):
            raw.validate_fixups(bytes.fromhex(doc["code_hex"]), doc["references"], doc["local_symbols"])
        doc = self.make().manifest()
        doc["references"][0]["local"] = 4
        with self.assertRaises(ValueError):
            raw.validate_fixups(bytes.fromhex(doc["code_hex"]), doc["references"], doc["local_symbols"])

    def test_insertion_policy_is_required(self):
        with self.assertRaises(TypeError):
            self.make().insert_before("fn.return", raw.ByteBlock().emit("90"))

class GeneratedFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exe = OUT/"generic.exe"
        silent(wb.new_image, cls.exe, ["KERNEL32.dll:ExitProcess", "KERNEL32.dll:ReadFile",
              "ADVAPI32.dll:RegisterServiceCtrlHandlerExW", "WS2_32.dll:WSAStartup"])

    def test_context_is_selective_and_measured(self):
        result = silent(wb.context_view, self.exe, "Entry")
        self.assertEqual(result["target"]["module"]["name"], "Entry")
        self.assertEqual(result["included"], [])
        payload = (json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)+"\n").encode()
        self.assertEqual(result["context_utf8_bytes"], len(payload))
        self.assertLess(result["read_stats"]["bytes_read"], self.exe.stat().st_size//10)

    def test_context_explicit_includes_and_budget_failure(self):
        result = silent(wb.context_view, self.exe, "Entry", include=["Data.AppContext"])
        self.assertEqual([item["module"]["name"] for item in result["included"]], ["Data.AppContext"])
        self.assertNotIn("code_hex", result["included"][0])
        destination = OUT/"oversized-context.json"
        with self.assertRaises(ValueError):
            silent(wb.context_view, self.exe, "Entry", max_bytes=1, output=destination)
        self.assertFalse(destination.exists())

    def test_context_does_not_overwrite(self):
        destination = OUT/"existing-context.json"
        destination.write_text("keep")
        with self.assertRaises(ValueError):
            silent(wb.context_view, self.exe, "Entry", output=destination)
        self.assertEqual(destination.read_text(), "keep")

    def test_inventory_supports_raw_and_annotated(self):
        with wb.PE(self.exe, metadata=False) as pe:
            entries = wb.import_inventory(pe)
        self.assertEqual([entry["dll"] for entry in entries], ["KERNEL32.dll", "ADVAPI32.dll", "WS2_32.dll"])
        self.assertEqual(sum(len(entry["functions"]) for entry in entries), 4)

    @unittest.skipUnless(os.name=="nt", "Windows native resolver")
    def test_real_system_exports_and_missing_export(self):
        with wb.PE(self.exe, metadata=False) as pe:
            wb.resolve_system_imports(wb.import_inventory(pe))
        with self.assertRaisesRegex(ValueError, "Unresolved system import"):
            wb.resolve_system_imports([{"dll":"KERNEL32.dll","functions":[{"name":"ThisExportDoesNotExist_987"}]}])

    @unittest.skipUnless(os.name=="nt", "Windows native execution")
    def test_named_hooks_route_native_exit_status(self):
        # Observable runtime regression: branches include a new status-setting hook or skip it.
        for policy, status in [("include", 42), ("skip", 0)]:
            block = raw.ByteBlock().emit("4883ec38 31c9")
            block.relative("e9", "entry.exit", kind="branch").label("entry.exit")
            block.relative("ff15", "iat.ExitProcess", kind="import").emit("4883c438c3")
            block.insert_before("entry.exit", raw.ByteBlock().emit("b9 2a000000"), branch_targets=policy)
            patch_path = OUT/(policy+".json")
            silent(wb.template, self.exe, "Entry", patch_path)
            patch = json.loads(patch_path.read_text())
            patch["hex"] = bytes(block.code).hex()
            patch["documentation"] = block.update_document(patch["documentation"])
            patch["documentation"]["purpose"] = "Native branch-hook regression, status "+str(status)
            patch["reason"] = "Verify explicit branch insertion policy through actual process status."
            patch_path.write_bytes(wb.canonical(patch))
            candidate = OUT/(policy+".exe")
            silent(wb.patch, self.exe, patch_path, candidate)
            result = subprocess.run([str(candidate)], capture_output=True, timeout=10,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(result.returncode, status)


class ConciseToolkitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exe=OUT/"concise.exe"
        silent(wb.new_image,cls.exe,["KERNEL32.dll:ExitProcess"])

    def test_concise_storage_and_legacy_reading(self):
        with wb.PE(self.exe) as pe:
            r=pe.record("Entry");brief=pe.brief(r);full=pe.document(r)
            self.assertTrue(r["flags"]&wb._meta.FLAG)
            self.assertNotIn("references",brief);self.assertNotIn("implementation",brief)
            self.assertIn("references",full)
            self.assertEqual(brief["imports"],["ExitProcess"])
            self.assertLess(r["doc_size"],1000)
        with wb.PE(ROOT/"examples/starfall/architecture/Starfall-v2.exe") as pe:
            self.assertEqual(pe.document(pe.record("Move"))["name"],"Move")
            self.assertEqual(pe.brief(pe.record("Move"))["calls"],[])

    def test_compact_is_deterministic_and_preserves_every_body(self):
        copy=OUT/"compacted.exe"
        silent(wb.compact_image,self.exe,copy)
        self.assertEqual(wb.stream_hash(copy),wb.stream_hash(self.exe))
        with wb.PE(copy) as a,wb.PE(self.exe) as b:
            for r in a.records:
                self.assertEqual(r["entry"],b.record(r["name"])["entry"])
                if r["kind"]==1:self.assertEqual(a.code(r),b.code(b.record(r["name"])))

    def test_named_get_has_correct_address_and_only_selected_bytes(self):
        result=silent(wb.get_view,self.exe,"Entry",True)
        with wb.PE(self.exe) as pe:
            r=pe.record("Entry")
            self.assertEqual(result["address"]["file_offset"],pe.offset(r["impl"]))
            self.assertEqual(bytes.fromhex(result["code_hex"]),pe.code(r))
        self.assertTrue(result["code_hash_matches"]);self.assertNotIn("edit_records",result)

    def test_overview_and_declared_graph(self):
        fixture=ROOT/"examples/starfall/Starfall.exe"
        view=silent(wb.overview_view,fixture)
        self.assertEqual(len(view["functions"]),45)
        self.assertFalse(any("code_hex" in f for f in view["functions"]))
        graph=silent(wb.graph_view,fixture,"MeteorHit")
        self.assertIn(["ProjectileStep","MeteorHit"],graph["edges"])
        self.assertNotIn(["Tick","PickupCollect"],graph["edges"])
        self.assertIn("indirect",graph["scope"])

    def test_budget_failure_and_output_protection(self):
        output=OUT/"small-view.json"
        with self.assertRaises(ValueError):silent(wb.get_view,self.exe,"Entry",True,output=output,max_bytes=1)
        self.assertFalse(output.exists())
        output.write_text("keep")
        with self.assertRaises(ValueError):silent(wb.overview_view,self.exe,output=output)
        self.assertEqual(output.read_text(),"keep")

    def test_contract_addresses_distinguish_file_bytes_and_virtual_storage(self):
        view=silent(wb.get_view,self.exe,"Data.AppContext")
        with wb.PE(self.exe) as pe:
            self.assertEqual(view["address"]["data_rva"],0x15000)
            self.assertEqual(view["address"]["file_offset"],pe.offset(0x15000))
        view=silent(wb.get_view,ROOT/"examples/starfall/Starfall.exe","Data.Upgrades")
        self.assertEqual(view["address"]["data_rva"],0x18500)
        self.assertIsNone(view["address"]["file_offset"])

    def test_reported_metadata_space_accounts_for_technical_tail(self):
        with wb.PE(self.exe) as pe:
            r=pe.record("Entry");d=pe.document(r);free=wb.metadata_free(r)
        self.assertLess(free,r["doc_capacity"]-r["doc_size"]-1)
        exact=copy.deepcopy(d);exact["purpose"]+="x"*free
        wb._meta.pack(exact,r)
        exact["purpose"]+="x"
        with self.assertRaisesRegex(ValueError,"slot exhausted"):wb._meta.pack(exact,r)

    def test_technical_corruption_is_detected(self):
        corrupted=OUT/"technical-corruption.exe";shutil.copyfile(self.exe,corrupted)
        with wb.PE(corrupted) as pe:at=pe.offset(pe.record("Entry")["technical_rva"])+wb._meta.HEADER
        data=bytearray(corrupted.read_bytes());data[at]^=1;corrupted.write_bytes(data)
        with self.assertRaisesRegex(ValueError,"hash mismatch"):silent(wb.verify,corrupted)

    def test_fixed_profiles_rebase_whole_instruction_fields(self):
        body=raw.ByteBlock().relative("ff15","iat.ExitProcess",kind="import")
        framed=body.framed("stack56");manifest=framed.manifest()
        self.assertEqual(manifest["references"][0]["offset"],6)
        self.assertEqual(manifest["references"][0]["next_offset"],10)
        self.assertEqual(bytes(framed.code[:4]),bytes.fromhex("4883ec38"))
        self.assertEqual(bytes(framed.code[-5:]),bytes.fromhex("4883c438c3"))
        module=raw.function_module("Operation",raw.ByteBlock().emit("31c0"),entry_rva=0x1b000,
            slot_bytes=256,profile="leaf",inputs={},returns="EAX=0",contracts=[],purpose="Return zero.")
        self.assertEqual(module["code_hex"],"31c0c3")
        self.assertEqual(module["document"]["implementation"]["used_bytes"],3)

    @unittest.skipUnless(os.name=="nt","Windows native execution")
    def test_direct_byte_edit_and_sync_changes_actual_exit_status(self):
        edited=OUT/"direct-edit.exe";shutil.copyfile(self.exe,edited)
        with wb.PE(edited) as pe:
            r=pe.record("Entry");doc=pe.document(r);symbols=pe.document(pe.record("Symbols"))["symbols"]
            body=raw.ByteBlock().emit("b92a000000").relative("ff15","iat.ExitProcess",kind="import")
            block=body.framed("stack56");doc=block.update_document(doc)
            code=wb.patch_references(doc,bytes(block.code),symbols,r["impl"])
            offset=pe.offset(r["impl"])
        data=bytearray(edited.read_bytes());data[offset:offset+len(code)]=code;edited.write_bytes(data)
        got=silent(wb.get_view,edited,"Entry",True,raw=True)
        self.assertFalse(got["code_hash_matches"])
        rejected=OUT/"bad-sync.exe"
        with self.assertRaises(ValueError):silent(wb.sync_image,edited,"Entry",rejected,len(code))
        self.assertFalse(rejected.exists());self.assertFalse(Path(str(rejected)+".building").exists())
        manifest=OUT/"direct-edit.manifest.json";manifest.write_bytes(wb.canonical(doc))
        output=OUT/"synchronized.exe";silent(wb.sync_image,edited,"Entry",output,len(code),manifest)
        result=subprocess.run([str(output)],capture_output=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode,42)
        with wb.PE(output) as pe:self.assertEqual(pe.code(pe.record("Entry")),code)

    def test_stale_technical_revision_rejects_patch(self):
        template=OUT/"technical-revision.patch.json";silent(wb.template,self.exe,"Entry",template)
        patch=json.loads(template.read_text());patch["expected_technical_sha256"]="00"*32
        template.write_bytes(wb.canonical(patch))
        output=OUT/"stale-technical.exe"
        with self.assertRaisesRegex(ValueError,"technical records"):silent(wb.patch,self.exe,template,output)
        self.assertFalse(output.exists())

class FakeFunctionPE:
    def __init__(self, block, mutate=None):
        manifest = block.manifest()
        self.code_bytes = wb.patch_references(manifest, bytes(block.code), {"output":0x5000}, 0x1000)
        self.doc = dict(name="Operation", references=manifest["references"], local_symbols=manifest["local_symbols"])
        if mutate:
            mutate(self.doc)
    def record(self, name):
        return dict(kind=1, impl=0x1000)
    def document(self, rec):
        return self.doc
    def code(self, rec):
        return self.code_bytes

@unittest.skipUnless(capstone is not None, "Optional Capstone analyzer absent")
class StaticAuditTests(unittest.TestCase):
    def analyze(self, block, mutate=None):
        return wb.analyze_function(FakeFunctionPE(block, mutate), "Operation", capstone)

    def test_correct_rip_immediate_tail(self):
        result = self.analyze(raw.ByteBlock().relative("c705", "output", "01000000").emit("c3"))
        self.assertTrue(result["valid"], result["errors"])

    def test_middle_of_instruction_branch_rejected(self):
        block = raw.ByteBlock().emit("e9 01000000 b8 01000000 c3")
        result = self.analyze(block)
        self.assertFalse(result["valid"])
        self.assertTrue(any("middle" in value for value in result["errors"]))

    def test_wrong_instruction_end_rejected(self):
        def change(doc):
            doc["references"][0]["next_offset"] = 6
        result = self.analyze(raw.ByteBlock().relative("c705", "output", "01000000").emit("c3"), change)
        self.assertFalse(result["valid"])

    def test_undeclared_relative_field_rejected(self):
        result = self.analyze(raw.ByteBlock().emit("48 8b05 00000000 c3"))
        self.assertFalse(result["valid"])

    def test_unreachable_instructions_reported_as_clues(self):
        block = raw.ByteBlock().relative("e9", "fn.return", kind="branch").emit("90").label("fn.return").emit("c3")
        result = self.analyze(block)
        self.assertTrue(result["valid"])
        self.assertEqual(result["unreachable_instruction_offsets"], [5])

if __name__=="__main__":
    program=unittest.main(exit=False)
    evidence=ROOT/"out"/"evidence";evidence.mkdir(parents=True,exist_ok=True)
    (evidence/("audit.json" if rest==["StaticAuditTests"] else "primitives.json")).write_text(json.dumps(dict(tests=program.result.testsRun,
        failures=len(program.result.failures),errors=len(program.result.errors),skipped=len(program.result.skipped)),indent=2)+"\n")
    if program.result.wasSuccessful():
        # Only this process-owned temp path, resolved beneath the intended workspace.
        if OUT.resolve().parent!=WORK.resolve() or not OUT.resolve().is_relative_to((ROOT/"out").absolute()) or OUT.is_symlink():raise RuntimeError("Unsafe test workspace")
        shutil.rmtree(OUT)
    raise SystemExit(0 if program.result.wasSuccessful() else 1)
