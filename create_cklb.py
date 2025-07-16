#!/usr/bin/env python3
"""
generate_cklb.py: Convert an XCCDF STIG XML into a CKLB JSON file for eMASS ingestion.
"""
import argparse
import os
import uuid
import json
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

try:
    import jsonschema
except ImportError:
    jsonschema = None

# Namespace mapping for XCCDF 1.1
NS = {'xccdf': 'http://checklists.nist.gov/xccdf/1.1'}

def parse_benchmark(tree):

    root = tree.getroot()
    stig_name = root.find('xccdf:title', NS).text or ""
    stig_id = root.get('id') or ""
    release_info = root.find("xccdf:plain-text[@id='release-info']", NS).text or ""
    stig_version = root.find('xccdf:version', NS).text or ""
    return stig_name, stig_id, release_info, stig_version

def parse_rules(tree, input_file, stig_uuid):
    root = tree.getroot()
    rules = []
    mtime = datetime.fromtimestamp(os.path.getmtime(input_file), timezone.utc).isoformat()
    for grp in root.findall('xccdf:Group', NS):
        rule_elem = grp.find('xccdf:Rule', NS)
        if rule_elem is None:
            continue
        gid_src = grp.get('id') or ""
        rid_src = rule_elem.get('id') or ""
        pretty_rid = rid_src.replace('_rule', '')

        # group metadata
        group_title = grp.find('xccdf:title', NS).text or ""
        group_desc = grp.find('xccdf:description', NS).text or ""

        # description sections
        desc_elem = rule_elem.find('xccdf:description', NS)
        desc_data = {}
        for sec in ['VulnDiscussion','FalsePositives','FalseNegatives','Documentable',
                    'SeverityOverrideGuidance','PotentialImpacts','ThirdPartyTools',
                    'Mitigations','MitigationControl','Responsibility','IAControls']:
            node = desc_elem.find(f'xccdf:{sec}', NS) if desc_elem is not None else None
            desc_data[sec.lower()] = node.text.strip() if node is not None and node.text else ""

        # Robustly extract VulnDiscussion: prefer direct child, else from description
        vuln_discussion_elem = rule_elem.find('xccdf:VulnDiscussion', NS)
        if vuln_discussion_elem is not None and vuln_discussion_elem.text:
            discussion = vuln_discussion_elem.text.strip()
        else:
            # Try to extract from desc_data (real element under description)
            discussion = desc_data.get('vulndiscussion', '')
            # If still empty, try to parse as HTML-escaped text
            if not discussion and desc_elem is not None and desc_elem.text:
                import re
                desc_text = desc_elem.text
                m = re.search(r'<VulnDiscussion>(.*?)</VulnDiscussion>', desc_text, re.DOTALL)
                if m:
                    discussion = m.group(1).strip()

        # extract fix text: handle both nested and flat
        fix_text = ""
        fix_elem = rule_elem.find('xccdf:fix/xccdf:fixtext', NS)
        if fix_elem is None:
            fix_elem = rule_elem.find('xccdf:fixtext', NS)
        if fix_elem is not None and fix_elem.text:
            fix_text = fix_elem.text.strip()

        # check content
        check = rule_elem.find('xccdf:check', NS)
        check_content = ''
        check_ref = None
        if check is not None:
            cc = check.find('xccdf:check-content', NS)
            if cc is not None and cc.text:
                check_content = cc.text.strip()
            cr = check.find('xccdf:check-content-ref', NS)
            if cr is not None:
                check_ref = {'href': cr.get('href'), 'name': cr.get('name')}

        # identifiers (CCI)
        ccis = [ident.text for ident in rule_elem.findall("xccdf:ident[@system='http://cyber.mil/cci']", NS)]
        ref_id = ccis[0] if ccis else None

        # ensure all required fields per schema
        r = {
            "evaluate-stig": {
                "answer_file": os.path.basename(input_file),
                "last_write": mtime + 'Z',
                "afmod": False,
                "old_status": "",
                "new_status": ""
            },
            "group_id_src": gid_src,
            "group_tree": [{"id": gid_src, "title": group_title, "description": group_desc}],
            "group_id": gid_src,
            "group_title": group_title,
            "severity": rule_elem.get('severity'),
            "rule_id_src": rid_src,
            "rule_id": pretty_rid,
            "rule_version": rule_elem.find('xccdf:version', NS).text or "",
            "rule_title": rule_elem.find('xccdf:title', NS).text or "",
            "fix_text": fix_text,
            "weight": rule_elem.get('weight'),
            "check_content": check_content,
            "check_content_ref": check_ref,
            "classification": "UNCLASSIFIED",
            "discussion": discussion,
            "false_positives": desc_data.get('falsepositives',''),
            "false_negatives": desc_data.get('falsenegatives',''),
            "documentable": desc_data.get('documentable',''),
            "security_override_guidance": desc_data.get('severityoverrideguidance',''),
            "potential_impacts": desc_data.get('potentialimpacts',''),
            "third_party_tools": desc_data.get('thirdpartytools',''),
            "mitigations": desc_data.get('mitigations',''),
            "mitigation_control": desc_data.get('mitigationcontrol',''),
            "responsibility": desc_data.get('responsibility',''),
            "ia_controls": desc_data.get('iacontrols',''),
            "legacy_ids": [],
            "ccis": ccis,
            "reference_identifier": ref_id,
            "uuid": str(uuid.uuid4()),
            "stig_uuid": stig_uuid,
            "status": "not_reviewed",
            "overrides": {},
            "comments": "",
            "finding_details": ""
        }
        # Add all required fields as empty string if missing (per schema)
        for required in [
            "group_id_src", "group_tree", "group_id", "group_title", "severity", "rule_id_src", "rule_id",
            "rule_version", "rule_title", "fix_text", "weight", "check_content", "check_content_ref",
            "classification", "discussion", "false_positives", "false_negatives", "documentable",
            "security_override_guidance", "potential_impacts", "third_party_tools", "mitigations",
            "mitigation_control", "responsibility", "ia_controls", "legacy_ids", "ccis", "reference_identifier",
            "uuid", "stig_uuid", "status", "overrides", "comments", "finding_details"
        ]:
            if required not in r:
                r[required] = "" if required not in ["legacy_ids", "ccis", "group_tree", "overrides"] else ([] if required in ["legacy_ids", "ccis", "group_tree"] else {})
        rules.append(r)
    return rules

def ensure_schema_compliance_rule(rule):
    # All fields from schema, with correct types
    schema_fields = {
        "uuid": "",
        "stig_uuid": "",
        "group_id": "",
        "group_id_src": "",
        "rule_id": "",
        "rule_id_src": "",
        "target_key": None,
        "stig_ref": None,
        "weight": "",
        "classification": "",
        "severity": "unknown",
        "rule_version": "",
        "rule_title": "",
        "fix_text": "",
        "reference_identifier": None,
        "group_title": "",
        "false_positives": "",
        "false_negatives": "",
        "discussion": "",
        "check_content": "",
        "documentable": "",
        "mitigations": "",
        "potential_impacts": "",
        "third_party_tools": "",
        "mitigation_control": "",
        "responsibility": "",
        "security_override_guidance": "",
        "ia_controls": "",
        "check_content_ref": None,
        "legacy_ids": [],
        "ccis": [],
        "group_tree": [],
        "status": "not_reviewed",
        "overrides": {},
        "comments": "",
        "finding_details": ""
    }
    # Only keep fields in schema, fill missing
    clean = {k: rule[k] if k in rule else v for k, v in schema_fields.items()}
    # Fix types
    if not isinstance(clean["legacy_ids"], list):
        clean["legacy_ids"] = []
    if not isinstance(clean["ccis"], list):
        clean["ccis"] = []
    if not isinstance(clean["group_tree"], list):
        clean["group_tree"] = []
    if not isinstance(clean["overrides"], dict):
        clean["overrides"] = {}
    # Enforce status enum
    if clean["status"] not in ["not_reviewed", "not_applicable", "open", "not_a_finding"]:
        clean["status"] = "not_reviewed"
    return clean

def ensure_schema_compliance_stig(stig):
    # Only keep allowed fields
    allowed = [
        "evaluate-stig", "stig_name", "display_name", "stig_id", "release_info", "uuid", "reference_identifier",
        "size", "rules", "version"
    ]
    clean = {k: stig[k] for k in allowed if k in stig}
    # Fill required
    for req in ["stig_name", "display_name", "stig_id", "release_info", "uuid", "size", "rules"]:
        if req not in clean:
            clean[req] = "" if req != "rules" and req != "size" else ([] if req == "rules" else 0)
    # Clean rules
    clean["rules"] = [ensure_schema_compliance_rule(r) for r in clean["rules"]]
    return clean

def ensure_schema_compliance_cklb(cklb):
    allowed = [
        "evaluate-stig", "title", "id", "cklb_version", "active", "mode", "has_path", "target_data", "stigs"
    ]
    clean = {k: cklb[k] for k in allowed if k in cklb}
    # Fill required
    for req in ["title", "id"]:
        if req not in clean:
            clean[req] = ""
    # Clean stigs
    if "stigs" in clean:
        clean["stigs"] = [ensure_schema_compliance_stig(s) for s in clean["stigs"]]
    return clean

def build_cklb(tree, input_file):
    stig_name, stig_id, release_info, stig_version = parse_benchmark(tree)
    stig_uuid = str(uuid.uuid4())
    rules = parse_rules(tree, input_file, stig_uuid)
    ref_id = rules[0]['reference_identifier'] if rules else None
    stig_obj = {
        "evaluate-stig": {"time": datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),
                           "module": {"name": "cklb_generator", "version": "1.1"}},
        "stig_name": stig_name,
        "display_name": stig_name.replace("Security Technical Implementation Guide","STIG"),
        "stig_id": stig_id,
        "release_info": release_info,
        "version": stig_version,
        "uuid": stig_uuid,
        "size": len(rules),
        "reference_identifier": ref_id,
        "rules": rules
    }
    cklb = {"evaluate-stig": {"version": "1.0"},
            "title": stig_name,
            "id": str(uuid.uuid4()),
            "stigs": [stig_obj],
            "active": True,
            "mode": 2,
            "has_path": False,
            "target_data": {"target_type": "host","host_name": "","ip_address": "", 
                             "mac_address": "","fqdn": "","comments": "","role": "",  
                             "is_web_database": False,"technology_area": "","web_db_site": "","web_db_instance": ""},
            "cklb_version": "1.0"}
    # Enforce schema compliance
    return ensure_schema_compliance_cklb(cklb)

def generate_cklb_json(input_file):
    tree = ET.parse(input_file)
    cklb = build_cklb(tree, input_file)
    return cklb

def convert_xccdf_zip_to_cklb(zip_path, cklb_dir):
    """
    Extracts all XCCDF XMLs from a zip file and converts each to CKLB, saving to cklb_dir.
    Returns a list of (cklb_path, error_message) for each file processed.
    Cleans up the zip and any extracted files from tmp after processing.
    """
    import zipfile, glob, tempfile, subprocess, sys, os, shutil
    file_name = os.path.basename(zip_path)
    results = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            with tempfile.TemporaryDirectory() as extract_dir:
                zip_ref.extractall(extract_dir)
                # Find all XCCDF XML files recursively
                xml_candidates = glob.glob(os.path.join(extract_dir, '**', '*xccdf*.xml'), recursive=True)
                if not xml_candidates:
                    xml_candidates = glob.glob(os.path.join(extract_dir, '**', '*.xml'), recursive=True)
                if not xml_candidates:
                    # Clean up zip file from tmp
                    if os.path.exists(zip_path):
                        try:
                            os.remove(zip_path)
                        except Exception:
                            pass
                    return [(None, f"[CKLB ERROR] No XCCDF XML found in zip: {file_name}")]
                for xccdf_xml in xml_candidates:
                    cklb_name = os.path.splitext(os.path.basename(xccdf_xml))[0] + ".cklb"
                    cklb_path = os.path.join(cklb_dir, cklb_name)
                    result = subprocess.run([
                        sys.executable, os.path.abspath(__file__),
                        xccdf_xml, cklb_path
                    ], capture_output=True, text=True)
                    if result.returncode == 0:
                        results.append((cklb_path, None))
                    else:
                        results.append((None, f"CKLB error: {result.stderr.strip()} for {os.path.basename(xccdf_xml)}"))
        # Clean up zip file from tmp after processing
        if os.path.exists(zip_path):
            try:
                os.remove(zip_path)
            except Exception:
                pass
        # Also clean up any extracted files in tmp (if any were copied there)
        tmp_dir = os.path.dirname(zip_path)
        if os.path.basename(tmp_dir) == "tmp":
            for f in os.listdir(tmp_dir):
                fpath = os.path.join(tmp_dir, f)
                if os.path.isfile(fpath) and (fpath.endswith('.xml') or fpath.endswith('.xccdf.xml')):
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass
        return results
    except Exception as e:
        # Clean up zip file from tmp on error
        if os.path.exists(zip_path):
            try:
                os.remove(zip_path)
            except Exception:
                pass
        return [(None, f"Download/CKLB error: {e}")]

def main():
    parser = argparse.ArgumentParser(description="Generate a CKLB JSON file from an XCCDF STIG XML")
    parser.add_argument('input_xml', help='Path to the XCCDF XML input')
    parser.add_argument('output_cklb', help='Path for the generated CKLB JSON')
    args = parser.parse_args()
    if not os.path.isfile(args.input_xml):
        print(f"Input file not found: {args.input_xml}")
        exit(1)
    tree = ET.parse(args.input_xml)
    cklb = build_cklb(tree, args.input_xml)
    with open(args.output_cklb,'w') as f:
        json.dump(cklb,f,indent=2)
    print(f"Generated CKLB file: {args.output_cklb}")

if __name__ == '__main__':
    main()
