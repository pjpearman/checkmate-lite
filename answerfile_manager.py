import logging
from pathlib import Path
from typing import Dict, List, Union, Iterable
import shutil
from datetime import datetime
import xml.etree.ElementTree as ET

from file_utils import safe_json_load, validate_file_ext

logger = logging.getLogger(__name__)

STATUS_MAP = {
    "open": "O",
    "not_reviewed": "NR",
    "not_a_finding": "NF",
    "not_applicable": "NA",
}


def load_cklb(path: Union[str, Path]) -> Dict:
    """
    Load a CKLB file with basic validation.
    """
    path = Path(path)
    if not validate_file_ext(path, [".cklb"]):
        raise ValueError(f"Unsupported file type for {path}. Expected .cklb")
    if not path.exists():
        raise FileNotFoundError(f"CKLB file not found: {path}")
    return safe_json_load(path)


def extract_non_nf_rules(cklb_data: Dict) -> List[Dict[str, str]]:
    """
    Return rules where status is in ['open', 'not_reviewed'] (case-insensitive).
    """
    stigs = cklb_data.get("stigs") or []
    if not stigs or not isinstance(stigs, list):
        logger.warning("No 'stigs' array found in CKLB data.")
        return []
    stig = stigs[0] or {}
    rules = stig.get("rules") or []
    if not isinstance(rules, list):
        logger.warning("No 'rules' array found in CKLB data.")
        return []

    filtered: List[Dict[str, str]] = []
    desired_statuses = {"open", "not_reviewed"}
    for rule in rules:
        status = str(rule.get("status", "")).strip()
        if status.lower() not in desired_statuses:
            continue
        filtered.append(
            {
                "group_id": str(rule.get("group_id", "")).strip(),
                "status": status,
                "group_title": str(rule.get("group_title", "")).strip(),
                "fix_text": str(rule.get("fix_text", "")).strip(),
                "comments": str(rule.get("comments", "")).strip(),
            }
        )
    return filtered


def map_cklb_status_to_answerfile(status: str) -> str | None:
    val = (status or "").strip().lower()
    return STATUS_MAP.get(val)


def _backup_file(path: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = path.with_suffix(f"{path.suffix}.{ts}.bak")
    shutil.copy2(path, backup)
    return backup


def save_answers_to_answerfile(answerfile_path: Union[str, Path], edits: Iterable[Dict[str, str]], stig_name: str | None = None) -> Dict[str, int]:
    """
    Merge edited answers into an AnswerFile XML. Creates Vuln/Answer nodes as needed.
    Returns summary dict: {'updated': int, 'created': int, 'skipped': int}
    """
    answerfile_path = Path(answerfile_path)
    if not answerfile_path.exists():
        raise FileNotFoundError(f"AnswerFile not found: {answerfile_path}")
    tree = ET.parse(answerfile_path)
    root = tree.getroot()
    if root.tag != "STIGComments":
        raise ValueError("Invalid AnswerFile: root element must be <STIGComments>")
    if stig_name and not root.get("Name"):
        root.set("Name", stig_name)

    summary = {"updated": 0, "created": 0, "skipped": 0}

    def find_or_create_vuln(vuln_id: str) -> ET.Element:
        for v in root.findall("Vuln"):
            if v.get("ID") == vuln_id:
                return v
        v = ET.SubElement(root, "Vuln")
        v.set("ID", vuln_id)
        return v

    def find_or_create_answerkey(vuln: ET.Element) -> ET.Element:
        for ak in vuln.findall("AnswerKey"):
            if ak.get("Name") == "DEFAULT":
                return ak
        ak = ET.SubElement(vuln, "AnswerKey")
        ak.set("Name", "DEFAULT")
        return ak

    def find_or_create_answer(answerkey: ET.Element, index: str = "1") -> ET.Element:
        for ans in answerkey.findall("Answer"):
            if ans.get("Index") == index:
                return ans
        ans = ET.SubElement(answerkey, "Answer")
        ans.set("Index", index)
        ans.set("ExpectedStatus", "")
        ans.set("Hostname", "")
        ans.set("Instance", "")
        ans.set("Database", "")
        ans.set("Site", "")
        ans.set("ResultHash", "")
        return ans

    for edit in edits:
        gid = edit.get("group_id") or edit.get("id")
        status = edit.get("status", "")
        comments = edit.get("comments", "") or ""
        if not gid:
            summary["skipped"] += 1
            continue
        mapped_status = map_cklb_status_to_answerfile(status)
        if not mapped_status:
            summary["skipped"] += 1
            continue
        vuln = find_or_create_vuln(str(gid))
        answerkey = find_or_create_answerkey(vuln)
        answer = find_or_create_answer(answerkey, "1")
        # Ensure child nodes exist
        def ensure_child(tag: str) -> ET.Element:
            child = answer.find(tag)
            if child is None:
                child = ET.SubElement(answer, tag)
            return child
        validation = ensure_child("ValidationCode")
        validation.text = validation.text or ""
        ensure_child("ValidTrueStatus").text = mapped_status
        ensure_child("ValidTrueComment").text = comments
        ensure_child("ValidFalseStatus").text = ""
        ensure_child("ValidFalseComment").text = ""
        answer.set("ExpectedStatus", mapped_status)
        summary["updated"] += 1

    # Backup then write
    _backup_file(answerfile_path)
    try:
        ET.indent(tree, space="  ")  # type: ignore[attr-defined]
    except Exception:
        pass
    tree.write(answerfile_path, encoding="utf-8", xml_declaration=True)
    return summary
