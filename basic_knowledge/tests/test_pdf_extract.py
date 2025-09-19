from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path

import pytest

from basic_knowledge.method_harvester import normalize, parser
from basic_knowledge.method_harvester.parser import extract_pdf_text
from basic_knowledge.scripts import harvest_methods

PDF_TEXT_SIMPLE_B64 = (
    "JVBERi0xLjQKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZy AvUGFnZXMgMi AwIFIgPj4KZW5kb2Jq"
    "CjIgMCBvYmoKPD wgL1R5cGU gL1BhZ2Vz IC9Db3Vud CAx IC9LaWRz IFsz IDAgUl0gPj4KZW5kb2Jq"
    "CjMgMCBvYmoKPD wgL1R5cGU gL1BhZ2 UgL1BhcmVud CAy IDAgUi AvTWVkaWFCb3ggWzAgMCA2MTIg"
    "NzkyXS AvQ29udGVud HMgNCAw IFIgL1Jlc291cmNlcy A8PCAvRm9ud CA8PCAvRjEgNS Aw IFIgPj4 g"
    "Pj4 gPj4KZW5kb2JqCjQgMC BvYmoKPD wgL0xlb md0a CA2MDMgPj4Kc3RyZWFtCkJUCi9GMS AxMi BU"
    "Zgox IDAgMCAx IDcy IDEwMC BUbQooRml2ZSBXaHlzKS BUagoxIDAgMCAx IDcyIDExOC BUbQooIyMj"
    "IE1vZGVsKS BUagoxIDAgMCAx ID72 IDEzNi BUbQooV2hlbiB0byB1c2U6KS BUagox IDAgMCAx ID72 IDE1NC"
    "BUbQooLS BJbnZlc3RpZ2F0ZSByZWN1cnJpbmcgaXNzdWVzIHF1aWNrbHkgd2l0aCBzaW1wbGUgcXVl"
    "c3Rpb25pbmcuKS BUagox IDAgMCAx ID72 IDE3Mi BUbQooU3RlcHM6KS BUagox IDAgMCAx ID72 IDE5MC BU"
    "bQooMS4gRGVmaW5lIHRoZSBwcm9ibGVtIHdpdGggb2JzZXJ2YWJsZSBmYWN0cyBhbmQgY29udGV4dC4p"
    "IFRqCjEgMCAwIDEgNzIgMjA4IFRtCigyLi BBc2sgd2h5IHJlcGVhdGVkbHkgdW50aWwgdGhlIHJvb3Qg"
    "Y2F1c2UgaXMgdW5kZXJzdG9vZC4p IFRqCjEgMCAwIDEgNzIgMjI2 IFRtCigzLi BBZGRyZXNzIHRoZSB1"
    "bmRlcmx5aW5nIGNhdXNlIHdpdGggY29ycmVjdGl2ZSBhY3Rpb24uKS BUagox IDAgMCAx ID72 IDI0NC BUbQ"
    "ooQW50aS1wYXR0ZXJuczop IFRqCjEgMCAw IDE gNzIgMjYy IFRtCigtIEFjY2VwdGluZyBzdXBlcmZpY2lh"
    "bCBhbnN3ZXJzIG9yIGJsYW1pbmcgaW5kaXZpZHVhbHMgcHJlbWF0dXJlbHkuKS BUagpFVAplbmRzdHJlYW0"
    "KZW5kb2JqCjUgMC BvYmoKPD wgL1R5cGU gL0Zvbn QgL1N1YnR5cGU gL1R5cGUx IC9CYXNlRm9ud C AvSGVs"
    "dmV0aWNh ID4+CmVuZG9iagp4cmVmCjAgNgowMDAwMDAwMDAw IDY1NTM1 IGY gCjAwMDAwMDAwMDkgMDAwMDA"
    "gbi AKMDAwMDAwMDA1OCAwMDAwMC Bu IAowMDAwMDAwMTE1 IDAwMDAw IG4 gCjAwMDAwMDAyNDE gMDAwMDAg"
    "bi AKMDAwMDAwMDg5NS AwMDAwMC Bu IAp0cmFpbGVyCjw8 IC9TaXpl IDY gL1Jvb3QgMS Aw IFIgPj4Kc3Rh"
    "cnR4cmVmCjk2NQolJUVPRgo="
)

PDF_BROKEN_XREF_B64 = (
    "JVBERi0xLjQKMS AwIG9iago8PCAvVHlwZS AvQ2F0YWxvZy AvUGFnZX MgMi Aw IFIgPj4KZW5kb2Jq"
    "CjIgMC BvYmoKPD wgL1R5cGU gL1BhZ2Vz IC9Db3Vud CAx IC9LaWRz IFsz IDAgUl0 gPj4KZW5kb2Jq"
    "CjMgMC BvYmoKPD wgL1R5cGU gL1BhZ2 UgL1BhcmVud CAy IDAgUi AvTWVkaWFCb3ggWzAgMCA2MTIg"
    "NzkyXS AvQ29udGVud HMgNCAw IFIgL1Jlc291cmNlcy A8PCAvRm9ud CA8PCAvRjEgNS Aw IFIgPj4 g"
    "Pj4 gPj4KZW5kb2JqCjQgMC BvYmoKPD wgL0xlb md0a CAzMjIgPj4Kc3RyZWFtCkJUCi9GMS AxMi BU"
    "Zgox IDAgMCAx ID72 IDEwMC BUbQooRGVjaXNpb24gTWF0cml4KS BUagox IDAgMCAx ID72 IDExOC BUbQ"
    "ooVXNlIHdoZW46KS BUagox IDAgMCAx ID72 IDEzNi BUbQooLS BD b21wYXJpbmc gbXVsdGlwbGUgb3B0aW9u"
    "cyB3aXRoIHdlaWdodGVkIGNyaXRlcmlhLikgVGoKMS Aw IDAgMS A3Mi AxNTQgVG0KKFN0ZXBzOik gVGoKMS Aw"
    "IDAgMS A3Mi AxNzIgVG0KKDEu IExpc3QgYWx0ZXJuYXRpdmVzLikgVGoKMS Aw IDAgMS A3Mi AxOTAgVG0KKDIu"
    "IERlZmluZ SBjcml0ZXJpYS4p IFRqCjEgMCAw IDE gNzIgMjA4 IFRtCigzLi BTY29yZ SBhbmQgc3VtLik gVGoKRVQ"
    "KZW5kc3RyZWFtCmVuZG9iago1 IDAgb2JqCjw8 IC9UeXBl IC9Gb250 IC9TdWJ0eXBl IC9UeXBlMS AvQmFzZUZv"
    "bnQgL0hlbHZldGljYSA+PgplbmRvYmoKeHJlZgow IDYKMDAwMDAwMDAwMCA2NTUzNS Bm IAowMDAwMDAwMDA5"
    "IDAwMDAw IG4 gCjAwMDAwMDAwNT ggMDAwMDA gbi AKMDAwMDAwMDExNS AwMDAwMC Bu IAowMDAwMDAwMjQx IDAw"
    "MDAw IG4 gCjAwMDAwMDA2MTQg MDAwMDA gbi AKdHJhaWxlcgo8PCAvU2l6Z SA2 IC9Sb290 IDE gMC BS ID4+"
    "CnN0YXJ0eHJlZgowCiUlRU9GCg=="
)

PDF_IMAGE_ONLY_B64 = (
    "JVBERi0xLjQKMS AwIG9iago8PCAvVHlwZS AvQ2F0YWxvZy AvUGFnZX MgMi Aw IFIgPj4KZW5kb2Jq"
    "CjIgMC BvYmoKPD wgL1R5cGU gL1BhZ2Vz IC9Db3Vud CAx IC9LaWRz IFsz IDAgUl0 gPj4KZW5kb2Jq"
    "CjMgMC BvYmoKPD wgL1R5cGU gL1BhZ2 UgL1BhcmVud CAy IDAgUi AvTWVkaWFCb3ggWzAgMCA2MTIg"
    "NzkyXS AvQ29udGVud HMgNCAw IFIgL1Jlc291cmNlcy A8PCAvRm9ud CA8PCAvRjEgNS Aw IFIgPj4 g"
    "Pj4 gPj4KZW5kb2JqCjQgMC BvYmoKPD wgL0xlb md0a CAxNSA+PgpzdHJlYW0KQlQKL0Yx IDEy IFRm"
    "CkVUCmVuZHN0cmVhbQplbmRvYmoKNS Aw IG9iago8PCAvVHlwZS AvRm9ud C AvU3VidHlwZS AvVHlwZTE gL0Jh"
    "c2VGb250 IC9IZWx2ZXRpY2 EgPj4KZW5kb2JqCnhyZWYKMCA2CjAwMDAwMDAwMDAgNjU1MzUgZi AKMDAwMDAw"
    "MDAwOS AwMDAwMC Bu IAowMDAwMDAwMDU4 IDAwMDAw IG4 gCjAwMDAwMDAxMTUgMDAwMDA gbi AKMDAwMDAwMDI0MS"
    "AwMDAwMC Bu IAowMDAwMDAwMzA2 IDAwMDAw IG4 gCnRyYWlsZXIKPDwgL1Npem UgNi AvUm9vd CAx IDAgUi A+Pgpz"
    "dGFydHhyZWYKMzc2CiUlRU9GCg=="
)

BACKENDS = ["pypdf", "pdfminer", "pikepdf+pypdf", "pikepdf+pdfminer"]


@pytest.fixture()
def pdf_text_simple(tmp_path: Path) -> Path:
    path = tmp_path / "five_whys.pdf"
    path.write_bytes(base64.b64decode(PDF_TEXT_SIMPLE_B64))
    return path


@pytest.fixture()
def pdf_broken_xref(tmp_path: Path) -> Path:
    path = tmp_path / "decision_matrix.pdf"
    path.write_bytes(base64.b64decode(PDF_BROKEN_XREF_B64))
    return path


@pytest.fixture()
def pdf_image_only(tmp_path: Path) -> Path:
    path = tmp_path / "diagram.pdf"
    path.write_bytes(base64.b64decode(PDF_IMAGE_ONLY_B64))
    return path


def test_extract_pdf_text_simple_pypdf_or_pdfminer_ok(
    tmp_path: Path, pdf_text_simple: Path
) -> None:
    text, meta = extract_pdf_text(pdf_text_simple, min_chars=200, prefer_backends=BACKENDS)
    assert text.strip()
    assert meta["chars"] >= 200
    assert meta["backend"] in set(BACKENDS)

    root = tmp_path / "repo"
    target = root / "basic_knowledge" / "method_frame"
    target.mkdir(parents=True)
    shutil.copy(pdf_text_simple, target / pdf_text_simple.name)

    items, files = parser.scan_directory(
        target, root, min_pdf_chars=200, pdf_backends=BACKENDS
    )
    names = {item.name for item in items}
    assert "Five Whys" in names
    rel_path = f"basic_knowledge/method_frame/{pdf_text_simple.name}"
    assert rel_path in files
    assert files[rel_path].pdf_meta is not None
    assert files[rel_path].pdf_meta.get("backend") in set(BACKENDS)


def test_extract_pdf_text_repairs_broken_xref(pdf_broken_xref: Path) -> None:
    text, meta = extract_pdf_text(pdf_broken_xref, min_chars=150, prefer_backends=BACKENDS)
    assert "Matrix" in text
    assert meta["backend"] in {"pdfminer", "pikepdf+pypdf", "pikepdf+pdfminer"}
    if meta["backend"].startswith("pikepdf"):
        assert meta.get("repaired")


def test_extract_pdf_text_image_only_returns_empty(
    tmp_path: Path, pdf_image_only: Path
) -> None:
    text, meta = extract_pdf_text(pdf_image_only, min_chars=150, prefer_backends=BACKENDS)
    assert text == ""
    assert meta["chars"] < 150
    assert meta["backend"] in {"none"} | set(BACKENDS)

    root = tmp_path / "repo"
    target = root / "basic_knowledge" / "method_frame"
    target.mkdir(parents=True)
    shutil.copy(pdf_image_only, target / pdf_image_only.name)
    _, files = parser.scan_directory(target, root, min_pdf_chars=150, pdf_backends=BACKENDS)
    rel_path = f"basic_knowledge/method_frame/{pdf_image_only.name}"
    assert rel_path in files
    assert files[rel_path].extracted_count == 0


def test_scan_report_pdf_meta_is_populated(
    tmp_path: Path, pdf_text_simple: Path, pdf_broken_xref: Path, pdf_image_only: Path
) -> None:
    root = tmp_path / "repo"
    target = root / "basic_knowledge" / "method_frame"
    target.mkdir(parents=True)
    for source in (pdf_text_simple, pdf_broken_xref, pdf_image_only):
        shutil.copy(source, target / source.name)

    items, files = parser.scan_directory(target, root, min_pdf_chars=180, pdf_backends=BACKENDS)
    assert items

    paths = harvest_methods.HarvesterPaths(root, target)
    timestamp = normalize.now_iso()
    harvest_methods.write_scan_report(paths, files, timestamp)

    report = json.loads(paths.scan_report_path.read_text(encoding="utf-8"))
    file_entries = report["files"]
    for filename in (
        f"basic_knowledge/method_frame/{pdf_text_simple.name}",
        f"basic_knowledge/method_frame/{pdf_broken_xref.name}",
        f"basic_knowledge/method_frame/{pdf_image_only.name}",
    ):
        assert filename in file_entries
        meta = file_entries[filename].get("pdf_meta")
        assert isinstance(meta, dict)
        assert meta.get("bytes", 0) > 0
        assert "backend" in meta
        assert "chars" in meta
        assert "warnings" in meta
        assert "repaired" in meta
        assert "error" in meta
