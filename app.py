from __future__ import annotations

import html
import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS


# ============================================================
# Environment helpers
# ============================================================

load_dotenv()


def get_env_required(name: str) -> str:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value.strip()


def get_env_optional(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def get_env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"true", "1", "yes", "y"}


def get_env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return int(value.strip())


# ============================================================
# Config
# ============================================================

SERVICENOW_INSTANCE_URL = get_env_required("SERVICENOW_INSTANCE_URL").rstrip("/")
SERVICENOW_USERNAME = get_env_required("SERVICENOW_USERNAME")
SERVICENOW_PASSWORD = get_env_required("SERVICENOW_PASSWORD")
SERVICENOW_TABLE = get_env_optional("SERVICENOW_TABLE", "sn_grc_issue")

ARCHER_API_BASE_URL = get_env_required("ARCHER_API_BASE_URL").rstrip("/")
ARCHER_SOAP_BASE_URL = get_env_required("ARCHER_SOAP_BASE_URL").rstrip("/")
ARCHER_INSTANCE_NAME = get_env_required("ARCHER_INSTANCE_NAME")
ARCHER_USERNAME = get_env_required("ARCHER_USERNAME")
ARCHER_PASSWORD = get_env_required("ARCHER_PASSWORD")

VERIFY_SSL = get_env_bool("VERIFY_SSL", True)
REQUEST_TIMEOUT_SECONDS = get_env_int("REQUEST_TIMEOUT_SECONDS", 30)

FINDINGS_APPLICATION_GUID = get_env_required("FINDINGS_APPLICATION_GUID")

ARCHER_REVERSE_SYNC_DRY_RUN = get_env_bool("ARCHER_REVERSE_SYNC_DRY_RUN", True)
ARCHER_SEARCH_PAGE_SIZE = get_env_int("ARCHER_SEARCH_PAGE_SIZE", 500)
ARCHER_SEARCH_MAX_PAGES = get_env_int("ARCHER_SEARCH_MAX_PAGES", 100)

CORS_ORIGINS = [
    origin.strip()
    for origin in get_env_optional("CORS_ORIGINS", "").split(",")
    if origin.strip()
]

ARCHER_FIELDS = {
    "Finding ID": get_env_required("ARCHER_FIELD_FINDING_ID_GUID"),
    "Finding": get_env_required("ARCHER_FIELD_FINDING_GUID"),
    "Overall Status": get_env_optional("ARCHER_FIELD_OVERALL_STATUS_GUID", ""),
    "Response": get_env_optional("ARCHER_FIELD_RESPONSE_GUID", ""),
    "Assigned To": get_env_optional("ARCHER_FIELD_ASSIGNED_TO_GUID", ""),
    "Reviewer": get_env_optional("ARCHER_FIELD_REVIEWER_GUID", ""),
    "Business Response": get_env_optional("ARCHER_FIELD_BUSINESS_RESPONSE_GUID", ""),
}


# ============================================================
# Flask app
# ============================================================

app = Flask(__name__)

if CORS_ORIGINS:
    CORS(app, origins=CORS_ORIGINS)
else:
    CORS(app)


# ============================================================
# General helpers
# ============================================================

def clean_html_text(value: Any) -> str:
    if value is None:
        return ""

    text = str(value)

    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</p\s*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)

    text = html.unescape(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    lines = [line.strip() for line in text.split("\n")]
    lines = [line for line in lines if line]

    return "\n".join(lines).strip()


def safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def extract_archer_id_from_text(text: str) -> Optional[str]:
    if not text:
        return None

    match = re.search(r"\[ARCHER_ID\s*:\s*(FND-\d+)\]", text, flags=re.IGNORECASE)
    if match:
        return match.group(1).upper()

    match = re.search(r"\bFND-\d+\b", text, flags=re.IGNORECASE)
    if match:
        return match.group(0).upper()

    return None


def finding_id_to_tracking_number(finding_id: str) -> str:
    match = re.search(r"(\d+)", finding_id or "")
    if not match:
        raise ValueError(f"Could not extract numeric tracking number from finding_id: {finding_id}")
    return match.group(1)


def extract_finding_section(description: str) -> str:
    text = clean_html_text(description)

    marker_match = re.search(
        r"Finding\s*:\s*(.*)",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    if not marker_match:
        return text.strip()

    finding_text = marker_match.group(1).strip()

    stop_patterns = [
        r"\n\s*State\s*:",
        r"\n\s*Priority\s*:",
        r"\n\s*ServiceNow",
        r"\n\s*Sys ID\s*:",
        r"\n\s*Updated",
        r"\n\s*Created",
    ]

    for pattern in stop_patterns:
        stop_match = re.search(pattern, finding_text, flags=re.IGNORECASE)
        if stop_match:
            finding_text = finding_text[: stop_match.start()].strip()

    return finding_text.strip()


# ============================================================
# ServiceNow helpers
# ============================================================

def servicenow_headers() -> Dict[str, str]:
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def servicenow_table_url() -> str:
    return f"{SERVICENOW_INSTANCE_URL}/api/now/table/{SERVICENOW_TABLE}"


def normalize_archer_payload_for_servicenow(payload: Dict[str, Any]) -> Dict[str, Any]:
    finding_id = safe_str(
        payload.get("finding_id")
        or payload.get("Finding ID")
        or payload.get("archer_finding_id")
        or payload.get("id")
    )

    finding_text = safe_str(
        payload.get("finding")
        or payload.get("Finding")
        or payload.get("description")
        or payload.get("Description")
    )

    priority = safe_str(payload.get("priority") or payload.get("Priority"), "3")
    state = safe_str(payload.get("state") or payload.get("State"), "Open")

    if not finding_id:
        raise ValueError("Missing finding_id in Archer payload.")

    if not finding_id.upper().startswith("FND-"):
        finding_id = f"FND-{finding_id}"

    finding_id = finding_id.upper()

    short_description = f"Archer Finding {finding_id}"

    description = (
        f"[ARCHER_ID:{finding_id}]\n\n"
        f"Finding:\n"
        f"{finding_text}"
    )

    return {
        "archer_finding_id": finding_id,
        "short_description": short_description,
        "description": description,
        "priority": priority,
        "state": state,
    }


def find_existing_servicenow_issue_by_archer_id(archer_finding_id: str) -> Optional[Dict[str, Any]]:
    query = f"descriptionLIKE[ARCHER_ID:{archer_finding_id}]"

    response = requests.get(
        servicenow_table_url(),
        headers=servicenow_headers(),
        auth=(SERVICENOW_USERNAME, SERVICENOW_PASSWORD),
        params={
            "sysparm_query": query,
            "sysparm_limit": "1",
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    response.raise_for_status()

    data = response.json()
    results = data.get("result", [])

    if not results:
        return None

    return results[0]


def create_servicenow_issue(sn_payload: Dict[str, Any]) -> Dict[str, Any]:
    response = requests.post(
        servicenow_table_url(),
        headers=servicenow_headers(),
        auth=(SERVICENOW_USERNAME, SERVICENOW_PASSWORD),
        json={
            "short_description": sn_payload["short_description"],
            "description": sn_payload["description"],
            "priority": sn_payload["priority"],
            "state": sn_payload["state"],
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    response.raise_for_status()
    return response.json()


def update_servicenow_issue(sys_id: str, sn_payload: Dict[str, Any]) -> Dict[str, Any]:
    response = requests.patch(
        f"{servicenow_table_url()}/{sys_id}",
        headers=servicenow_headers(),
        auth=(SERVICENOW_USERNAME, SERVICENOW_PASSWORD),
        json={
            "short_description": sn_payload["short_description"],
            "description": sn_payload["description"],
            "priority": sn_payload["priority"],
            "state": sn_payload["state"],
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    response.raise_for_status()
    return response.json()


# ============================================================
# Archer REST helpers
# ============================================================

def archer_headers(token: Optional[str] = None) -> Dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    if token:
        headers["Authorization"] = f"Archer session-id={token}"

    return headers


def archer_login() -> str:
    url = f"{ARCHER_API_BASE_URL}/core/security/login"

    body = {
        "InstanceName": ARCHER_INSTANCE_NAME,
        "Username": ARCHER_USERNAME,
        "Password": ARCHER_PASSWORD,
    }

    response = requests.post(
        url,
        headers=archer_headers(),
        json=body,
        verify=VERIFY_SSL,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    response.raise_for_status()

    data = response.json()

    token = (
        data.get("RequestedObject", {}).get("SessionToken")
        or data.get("SessionToken")
        or data.get("sessionToken")
    )

    if not token:
        raise RuntimeError(f"Archer login succeeded but no token found. Response: {data}")

    return token


def get_archer_application_by_guid(token: str, application_guid: str) -> Dict[str, Any]:
    url = f"{ARCHER_API_BASE_URL}/core/system/application"

    response = requests.get(
        url,
        headers=archer_headers(token),
        verify=VERIFY_SSL,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    response.raise_for_status()

    data = response.json()

    # ── Fix: handle both list and dict responses ──────────────────
    requested = data.get("RequestedObject", data)

    if isinstance(requested, list):
        apps = requested
    elif isinstance(requested, dict):
        apps = requested.get("Applications", requested.get("Value", []))
        if not isinstance(apps, list):
            apps = [apps]
    else:
        apps = []
    # ─────────────────────────────────────────────────────────────

    for app_item in apps:
        if not isinstance(app_item, dict):
            continue
        guid = str(app_item.get("Guid") or app_item.get("GUID") or "").lower()
        if guid == application_guid.lower():
            return app_item

    raise RuntimeError(f"Could not find Archer application with GUID: {application_guid}")


def get_archer_field_ids(
    token: str,
    application_id: int,
    field_guid_map: Dict[str, str],
) -> Dict[str, int]:
    url = f"{ARCHER_API_BASE_URL}/core/system/fielddefinition/application/{application_id}"

    response = requests.get(
        url,
        headers=archer_headers(token),
        verify=VERIFY_SSL,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    response.raise_for_status()

    data = response.json()
    fields = data.get("RequestedObject", data)

    if isinstance(fields, dict):
        fields = fields.get("FieldDefinitions", fields.get("Value", []))

    if not isinstance(fields, list):
        raise RuntimeError(f"Could not parse Archer field definitions response: {data}")

    result: Dict[str, int] = {}

    for logical_name, target_guid in field_guid_map.items():
        if not target_guid:
            continue

        matched_field = None

        for field in fields:
            field_guid = str(field.get("Guid") or field.get("GUID") or "").lower()
            if field_guid == target_guid.lower():
                matched_field = field
                break

        if not matched_field:
            raise RuntimeError(
                f"Could not find Archer field '{logical_name}' with GUID {target_guid}"
            )

        field_id = matched_field.get("Id") or matched_field.get("ID")
        if field_id is None:
            raise RuntimeError(f"Matched Archer field '{logical_name}' but no Id found.")

        result[logical_name] = int(field_id)

    return result


def build_archer_field_contents_for_text_updates(
    field_ids: Dict[str, int],
    fields_to_update: Dict[str, str],
) -> Dict[str, Dict[str, Any]]:
    field_contents: Dict[str, Dict[str, Any]] = {}

    for field_name, value in fields_to_update.items():
        if field_name not in field_ids:
            raise RuntimeError(f"Field ID was not resolved for Archer field: {field_name}")

        field_id = field_ids[field_name]

        field_contents[str(field_id)] = {
            "FieldId": field_id,
            "Type": 1,
            "Value": value,
        }

    return field_contents


def try_archer_content_update(
    token: str,
    content_id: int,
    field_contents: Dict[str, Dict[str, Any]],
    level_id: int = 62,
) -> Dict[str, Any]:
    body = {
        "Content": {
            "Id": content_id,
            "LevelId": level_id,
            "FieldContents": field_contents,
        }
    }

    attempts: List[Dict[str, Any]] = []

    urls = [
        f"{ARCHER_API_BASE_URL}/core/content/{content_id}",
        f"{ARCHER_API_BASE_URL}/core/content",
    ]

    for url in urls:
        response = requests.put(
            url,
            headers=archer_headers(token),
            json=body,
            verify=VERIFY_SSL,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        attempt = {
            "url": url,
            "status_code": response.status_code,
            "ok": response.ok,
            "response_preview": response.text[:1000],
        }

        attempts.append(attempt)

        if response.ok:
            try:
                attempt["json"] = response.json()
            except Exception:
                pass

            return {
                "success": True,
                "working_attempt": attempt,
                "all_attempts": attempts,
            }

    return {
        "success": False,
        "all_attempts": attempts,
    }


# ============================================================
# Archer SOAP search helpers
# ============================================================

def archer_soap_headers() -> Dict[str, str]:
    return {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": "http://archer-tech.com/webservices/SearchRecordsByReport",
    }


def archer_soap_search_records(
    token: str,
    application_id: int,
    page_number: int,
    page_size: int,
    max_record_count: int,
) -> str:
    url = f"{ARCHER_SOAP_BASE_URL}/search.asmx"

    search_xml = f"""
<SearchReport>
  <PageSize>{page_size}</PageSize>
  <MaxRecordCount>{max_record_count}</MaxRecordCount>
  <DisplayFields>
    <DisplayField>{application_id}</DisplayField>
  </DisplayFields>
  <Criteria>
    <ModuleCriteria>
      <ApplicationId>{application_id}</ApplicationId>
    </ModuleCriteria>
  </Criteria>
</SearchReport>
""".strip()

    soap_body = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <SearchRecordsByReport xmlns="http://archer-tech.com/webservices/">
      <sessionToken>{token}</sessionToken>
      <pageNumber>{page_number}</pageNumber>
      <searchReport>{html.escape(search_xml)}</searchReport>
    </SearchRecordsByReport>
  </soap:Body>
</soap:Envelope>
"""

    response = requests.post(
        url,
        headers=archer_soap_headers(),
        data=soap_body.encode("utf-8"),
        verify=VERIFY_SSL,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    response.raise_for_status()
    return response.text


def parse_soap_search_records(
    soap_response_text: str,
    finding_id_field_id: int,
) -> List[Tuple[int, str]]:
    records: List[Tuple[int, str]] = []

    try:
        root = ET.fromstring(soap_response_text)
    except ET.ParseError:
        return records

    for elem in root.iter():
        if not elem.tag.lower().endswith("searchrecordsbyreportresult"):
            continue

        inner_xml = elem.text or ""
        inner_xml = html.unescape(inner_xml)

        if not inner_xml.strip():
            continue

        try:
            records_root = ET.fromstring(inner_xml)
        except ET.ParseError:
            continue

        for record in records_root.iter():
            if not record.tag.lower().endswith("record"):
                continue

            content_id_raw = (
                record.attrib.get("contentId")
                or record.attrib.get("contentid")
                or record.attrib.get("id")
            )

            if not content_id_raw:
                continue

            try:
                content_id = int(content_id_raw)
            except ValueError:
                continue

            finding_id_value = ""

            for field in record.iter():
                if not field.tag.lower().endswith("field"):
                    continue

                field_id_raw = field.attrib.get("id") or field.attrib.get("fieldId")
                if str(field_id_raw) == str(finding_id_field_id):
                    finding_id_value = clean_html_text(field.text or "")
                    break

            if finding_id_value:
                records.append((content_id, finding_id_value))

    return records


def find_archer_content_id_by_finding_id(
    token: str,
    application_id: int,
    finding_id_field_id: int,
    finding_id: str,
) -> int:
    target_tracking_number = finding_id_to_tracking_number(finding_id)

    page_size = ARCHER_SEARCH_PAGE_SIZE
    max_pages = ARCHER_SEARCH_MAX_PAGES
    max_record_count = page_size * max_pages

    for page_number in range(1, max_pages + 1):
        soap_text = archer_soap_search_records(
            token=token,
            application_id=application_id,
            page_number=page_number,
            page_size=page_size,
            max_record_count=max_record_count,
        )

        records = parse_soap_search_records(
            soap_response_text=soap_text,
            finding_id_field_id=finding_id_field_id,
        )

        if not records:
            break

        for content_id, field_value in records:
            if field_value.strip() == target_tracking_number:
                return content_id

    raise RuntimeError(
        f"Could not find Archer content ID for {finding_id}. "
        f"Looked for numeric Finding ID value '{target_tracking_number}'."
    )


# ============================================================
# Reverse sync payload builder
# ============================================================

def normalize_servicenow_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    description = safe_str(
        payload.get("description")
        or payload.get("Description")
        or payload.get("comments")
        or payload.get("work_notes")
    )

    short_description = safe_str(
        payload.get("short_description")
        or payload.get("Short description")
        or payload.get("title")
    )

    archer_finding_id = (
        safe_str(payload.get("archer_finding_id"))
        or extract_archer_id_from_text(description)
        or extract_archer_id_from_text(short_description)
    )

    if not archer_finding_id:
        raise ValueError(
            "Could not find Archer Finding ID. Expected marker like [ARCHER_ID:FND-1635]."
        )

    return {
        "archer_finding_id": archer_finding_id.upper(),
        "short_description": short_description,
        "description": description,
        "state": safe_str(payload.get("state") or payload.get("State")),
        "priority": safe_str(payload.get("priority") or payload.get("Priority")),
        "raw": payload,
    }


def build_archer_reverse_payload(sn_data: Dict[str, Any]) -> Dict[str, Any]:
    finding_text = extract_finding_section(sn_data["description"])

    if not finding_text:
        raise ValueError("Finding section is empty. Nothing to sync back to Archer.")

    return {
        "finding_id": sn_data["archer_finding_id"],
        "fields_to_update": {
            "Finding": finding_text,
        },
        "raw_servicenow": sn_data,
    }


def update_archer_record_real(archer_payload: Dict[str, Any]) -> Dict[str, Any]:
    token = archer_login()

    findings_app = get_archer_application_by_guid(
        token=token,
        application_guid=FINDINGS_APPLICATION_GUID,
    )

    application_id = int(findings_app["Id"])

    fields_needed = {
        "Finding ID": ARCHER_FIELDS["Finding ID"],
    }

    for field_name in archer_payload["fields_to_update"].keys():
        if field_name not in ARCHER_FIELDS:
            raise RuntimeError(f"Missing field GUID config for Archer field: {field_name}")

        field_guid = ARCHER_FIELDS[field_name]
        if not field_guid:
            raise RuntimeError(f"Empty field GUID config for Archer field: {field_name}")

        fields_needed[field_name] = field_guid

    field_ids = get_archer_field_ids(
        token=token,
        application_id=application_id,
        field_guid_map=fields_needed,
    )

    content_id = find_archer_content_id_by_finding_id(
        token=token,
        application_id=application_id,
        finding_id_field_id=field_ids["Finding ID"],
        finding_id=archer_payload["finding_id"],
    )

    field_contents = build_archer_field_contents_for_text_updates(
        field_ids=field_ids,
        fields_to_update=archer_payload["fields_to_update"],
    )

    update_result = try_archer_content_update(
        token=token,
        content_id=content_id,
        field_contents=field_contents,
    )

    return {
        "dry_run": False,
        "message": "Archer update attempted.",
        "finding_id": archer_payload["finding_id"],
        "archer_content_id": content_id,
        "field_contents_sent": field_contents,
        "update_result": update_result,
    }


# ============================================================
# Routes
# ============================================================

@app.route("/", methods=["GET"])
def root():
    return jsonify(
        {
            "service": "Archer-ServiceNow Middleware",
            "status": "running",
            "endpoints": [
                "/health",
                "/archer-to-servicenow",
                "/servicenow-to-archer",
            ],
        }
    ), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "archer-servicenow-middleware",
            "dry_run": ARCHER_REVERSE_SYNC_DRY_RUN,
        }
    ), 200


@app.route("/archer-to-servicenow", methods=["POST"])
def archer_to_servicenow():
    try:
        payload = request.get_json(force=True, silent=False)

        if not isinstance(payload, dict):
            return jsonify({"ok": False, "error": "Expected JSON object."}), 400

        sn_payload = normalize_archer_payload_for_servicenow(payload)

        existing_issue = find_existing_servicenow_issue_by_archer_id(
            sn_payload["archer_finding_id"]
        )

        if existing_issue:
            sys_id = existing_issue["sys_id"]
            result = update_servicenow_issue(sys_id, sn_payload)

            return jsonify(
                {
                    "ok": True,
                    "action": "updated",
                    "archer_finding_id": sn_payload["archer_finding_id"],
                    "servicenow_sys_id": sys_id,
                    "servicenow_response": result,
                }
            ), 200

        result = create_servicenow_issue(sn_payload)
        created_record = result.get("result", {})

        return jsonify(
            {
                "ok": True,
                "action": "created",
                "archer_finding_id": sn_payload["archer_finding_id"],
                "servicenow_sys_id": created_record.get("sys_id"),
                "servicenow_response": result,
            }
        ), 201

    except requests.HTTPError as exc:
        response = exc.response
        return jsonify(
            {
                "ok": False,
                "error": "ServiceNow HTTP error",
                "status_code": response.status_code if response else None,
                "response": response.text[:1000] if response else None,
            }
        ), 500

    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": str(exc),
            }
        ), 500


@app.route("/servicenow-to-archer", methods=["POST"])
def servicenow_to_archer():
    try:
        payload = request.get_json(force=True, silent=False)

        if not isinstance(payload, dict):
            return jsonify({"ok": False, "error": "Expected JSON object."}), 400

        sn_data = normalize_servicenow_payload(payload)
        archer_payload = build_archer_reverse_payload(sn_data)

        if ARCHER_REVERSE_SYNC_DRY_RUN:
            return jsonify(
                {
                    "ok": True,
                    "dry_run": True,
                    "message": "Dry run only. Archer was not updated.",
                    "archer_payload": archer_payload,
                }
            ), 200

        update_result = update_archer_record_real(archer_payload)

        return jsonify(
            {
                "ok": True,
                "dry_run": False,
                "archer_payload": archer_payload,
                "archer_update_result": update_result,
            }
        ), 200

    except requests.HTTPError as exc:
        response = exc.response
        return jsonify(
            {
                "ok": False,
                "error": "HTTP error during ServiceNow to Archer sync",
                "status_code": response.status_code if response else None,
                "response": response.text[:1000] if response else None,
            }
        ), 500

    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": str(exc),
            }
        ), 500


# ============================================================
# Temporary debug routes
# Remove these after Azure testing is complete
# ============================================================

@app.route("/debug-env", methods=["GET"])
def debug_env():
    required_vars = [
        "SERVICENOW_INSTANCE_URL",
        "SERVICENOW_USERNAME",
        "SERVICENOW_PASSWORD",
        "SERVICENOW_TABLE",
        "ARCHER_API_BASE_URL",
        "ARCHER_SOAP_BASE_URL",
        "ARCHER_INSTANCE_NAME",
        "ARCHER_USERNAME",
        "ARCHER_PASSWORD",
        "FINDINGS_APPLICATION_GUID",
        "ARCHER_FIELD_FINDING_ID_GUID",
        "ARCHER_FIELD_FINDING_GUID",
        "ARCHER_REVERSE_SYNC_DRY_RUN",
        "FLASK_DEBUG",
        "CORS_ORIGINS",
    ]

    result = {}

    for key in required_vars:
        value = os.getenv(key)
        result[key] = {
            "exists": value is not None and value.strip() != "",
            "preview": None if not value else value[:6] + "...",
        }

    return jsonify(result), 200


@app.route("/debug-servicenow", methods=["GET"])
def debug_servicenow():
    try:
        response = requests.get(
            servicenow_table_url(),
            headers=servicenow_headers(),
            auth=(SERVICENOW_USERNAME, SERVICENOW_PASSWORD),
            params={"sysparm_limit": "1"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        return jsonify(
            {
                "ok": response.ok,
                "status_code": response.status_code,
                "preview": response.text[:500],
            }
        ), response.status_code

    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": str(exc),
            }
        ), 500


@app.route("/debug-archer-login", methods=["GET"])
def debug_archer_login():
    try:
        token = archer_login()

        return jsonify(
            {
                "ok": True,
                "token_exists": bool(token),
                "token_preview": token[:6] + "..." if token else None,
            }
        ), 200

    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": str(exc),
            }
        ), 500


# ============================================================
# Local run only
# Azure uses Gunicorn startup command instead
# ============================================================

if __name__ == "__main__":
    app.run(
        host=get_env_optional("FLASK_HOST", "0.0.0.0"),
        port=get_env_int("PORT", get_env_int("FLASK_PORT", 5001)),
        debug=get_env_bool("FLASK_DEBUG", False),
    )