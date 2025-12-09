import logging
from pathlib import Path
from typing import Dict, List, Union

from file_utils import safe_json_load, validate_file_ext

logger = logging.getLogger(__name__)


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
