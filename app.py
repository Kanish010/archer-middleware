from __future__ import annotations

import html
import json as json_module
import os
import re
import traceback
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

FINDINGS_APPLICATION_GUID = get_env_optional("FINDINGS_APPLICATION_GUID", "")
FINDINGS_APPLICATION_ID = get_env_int("FINDINGS_APPLICATION_ID", 167)
FINDINGS_LEVEL_ID = get_env_int("FINDINGS_LEVEL_ID", 62)

ARCHER_FINDING_ID_FIELD_ID = get_env_int("ARCHER_FINDING_ID_FIELD_ID", 2260)
ARCHER_FINDING_TEXT_FIELD_ID = get_env_int("ARCHER_FINDING_TEXT_FIELD_ID", 2265)

ARCHER_REVERSE_SYNC_DRY_RUN = get_env_bool("ARCHER_REVERSE_SYNC_DRY_RUN", True)

CORS_ORIGINS = [
    origin.strip()
    for origin in get_env_optional("CORS_ORIGINS", "").split(",")
    if origin.strip()
]


# ============================================================
# Flask app
# ============================================================

app = Flask(__name__)

if CORS_ORIGINS:
    CORS(app, origins=CORS_ORIGINS)
else:
    CORS(app)


# ============================================================
# Robust payload parsing
# ============================================================

WRAPPER_KEYS = {
    "payload",
    "data",
    "record",
    "current",
    "body",
    "request",
    "result",
    "requestedobject",
    "content",
}


def parse_json_if_string(value: Any) -> Any:
    if not isinstance(value, str):
        return value

    text = value.strip()

    if not text:
        return value

    if not (
        (text.startswith("{") and text.endswith("}"))
        or (text.startswith("[") and text.endswith("]"))
    ):
        return value

    try:
        return json_module.loads(text)
    except Exception:
        return value


def unwrap_payload(data: Any) -> Dict[str, Any]:
    data = parse_json_if_string(data)

    if not isinstance(data, dict):
        return {}

    for key, value in list(data.items()):
        data[key] = parse_json_if_string(value)

    if len(data) == 1:
        only_key = next(iter(data.keys()))
        if str(only_key).lower() in WRAPPER_KEYS and isinstance(data[only_key], dict):
            return unwrap_payload(data[only_key])

    content_signals = {
        "finding_id",
        "finding",
        "description",
        "short_description",
        "state",
        "priority",
        "sys_id",
        "number",
        "archer_finding_id",
        "archer_content_id",
        "content_id",
        "finding id",
        "overall_status",
        "archerfindingid",
        "findingtext",
    }

    for key, value in list(data.items()):
        if str(key).lower() in WRAPPER_KEYS and isinstance(value, dict):
            inner_keys_lower = {str(k).lower() for k in value.keys()}
            normalized_inner_keys = {
                re.sub(r"[^a-z0-9]", "", str(k).lower())
                for k in value.keys()
            }

            if inner_keys_lower & content_signals or normalized_inner_keys & content_signals:
                return unwrap_payload(value)

    return data


def parse_inbound_request() -> Dict[str, Any]:
    payload: Any = None

    try:
        payload = request.get_json(force=False, silent=True)
    except Exception:
        payload = None

    if payload is not None:
        parsed = unwrap_payload(payload)
        if parsed:
            return parsed

    if request.form:
        form_dict = request.form.to_dict(flat=True)

        for _, value in form_dict.items():
            parsed_value = parse_json_if_string(value)
            if isinstance(parsed_value, dict):
                parsed = unwrap_payload(parsed_value)
                if parsed:
                    return parsed

        parsed = unwrap_payload(form_dict)
        if parsed:
            return parsed

    raw = request.get_data(as_text=True) or ""
    raw = raw.strip()

    if raw:
        parsed_raw = parse_json_if_string(raw)
        parsed = unwrap_payload(parsed_raw)
        if parsed:
            return parsed

    raise ValueError(
        f"Could not parse request body as JSON. "
        f"Content-Type: {request.content_type}. "
        f"Raw body preview: {raw[:300]}"
    )


def normalize_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def flex_get(data: Dict[str, Any], *candidate_keys: str, default: Any = None) -> Any:
    if not isinstance(data, dict):
        return default

    normalized_data = {normalize_key(k): v for k, v in data.items()}

    for candidate in candidate_keys:
        if candidate in data:
            val = data[candidate]
            if val is not None and str(val).strip():
                return val

        norm_candidate = normalize_key(candidate)
        if norm_candidate in normalized_data:
            val = normalized_data[norm_candidate]
            if val is not None and str(val).strip():
                return val

    for value in data.values():
        if isinstance(value, dict):
            found = flex_get(value, *candidate_keys, default=None)
            if found is not None and str(found).strip():
                return found

    return default


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


def safe_int(value: Any) -> Optional[int]:
    if value is None:
        return None

    match = re.search(r"\d+", str(value))
    if not match:
        return None

    return int(match.group(0))


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


def extract_archer_content_id_from_text(text: str) -> Optional[int]:
    if not text:
        return None

    match = re.search(r"\[ARCHER_CONTENT_ID\s*:\s*(\d+)\]", text, flags=re.IGNORECASE)
    if match:
        return int(match.group(1))

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
    payload = unwrap_payload(payload)

    finding_id = safe_str(
        flex_get(
            payload,
            "finding_id",
            "Finding ID",
            "FindingId",
            "archer_finding_id",
            "archerFindingId",
            "id",
            "tracking_id",
            "Tracking ID",
            "fnd_id",
            "FND ID",
        )
    )

    archer_content_id = safe_int(
        flex_get(
            payload,
            "archer_content_id",
            "archerContentId",
            "content_id",
            "contentId",
            "Content ID",
            "contentIdValue",
        )
    )

    finding_text = safe_str(
        flex_get(
            payload,
            "finding",
            "Finding",
            "finding_text",
            "Finding Text",
            "findingText",
            "description",
            "Description",
            "issue_description",
            "Issue Description",
        )
    )

    priority = safe_str(
        flex_get(payload, "priority", "Priority", "severity", "Severity"),
        "3",
    )

    state = safe_str(
        flex_get(payload, "state", "State", "status", "Status", "overall_status", "Overall Status"),
        "Open",
    )

    if not finding_id:
        raise ValueError(
            f"Missing finding_id in Archer payload. Received keys: {list(payload.keys())}"
        )

    if not finding_id.upper().startswith("FND-"):
        finding_id = f"FND-{finding_id}"

    finding_id = finding_id.upper()

    short_description = f"Archer Finding {finding_id}"

    content_marker = ""
    if archer_content_id:
        content_marker = f"[ARCHER_CONTENT_ID:{archer_content_id}]\n"

    description = (
        f"[ARCHER_ID:{finding_id}]\n"
        f"{content_marker}\n"
        f"Finding:\n"
        f"{finding_text}"
    )

    return {
        "archer_finding_id": finding_id,
        "archer_content_id": archer_content_id,
        "short_description": short_description,
        "description": description,
        "priority": priority,
        "state": state,
        "raw_archer_payload": payload,
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
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json=body,
        verify=VERIFY_SSL,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    response.raise_for_status()

    data = response.json()

    if isinstance(data, dict):
        requested = data.get("RequestedObject")
        token = (
            requested.get("SessionToken")
            if isinstance(requested, dict)
            else None
        ) or data.get("SessionToken") or data.get("sessionToken")
    else:
        token = None

    if not token:
        raise RuntimeError(f"Archer login succeeded but no token found. Response: {data}")

    return token


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
    level_id: int = FINDINGS_LEVEL_ID,
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

def archer_soap_search_records(
    token: str,
    application_id: int,
    finding_id_field_id: int,
    finding_id: str,
    page_number: int,
    page_size: int,
) -> str:
    url = f"{ARCHER_SOAP_BASE_URL}/search.asmx"

    tracking_number = finding_id_to_tracking_number(finding_id)

    search_xml = f"""<SearchReport>
    <PageSize>{page_size}</PageSize>
    <MaxRecordCount>{page_size}</MaxRecordCount>
    <ShowStatSummaries>false</ShowStatSummaries>
    <DisplayFields>
        <DisplayField>{finding_id_field_id}</DisplayField>
    </DisplayFields>
    <Criteria>
        <ModuleCriteria>
            <Module>{application_id}</Module>
            <IsKeywordModule>false</IsKeywordModule>
            <Filter>
                <Conditions>
                    <TextFilterCondition>
                        <Field>{finding_id_field_id}</Field>
                        <Operator>Equals</Operator>
                        <Value>{tracking_number}</Value>
                    </TextFilterCondition>
                </Conditions>
            </Filter>
        </ModuleCriteria>
    </Criteria>
</SearchReport>""".strip()

    soap_body = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ExecuteSearch xmlns="http://archer-tech.com/webservices/">
      <sessionToken>{token}</sessionToken>
      <searchOptions>{html.escape(search_xml)}</searchOptions>
      <pageNumber>{page_number}</pageNumber>
    </ExecuteSearch>
  </soap:Body>
</soap:Envelope>
"""

    response = requests.post(
        url,
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '"http://archer-tech.com/webservices/ExecuteSearch"',
        },
        data=soap_body.encode("utf-8"),
        verify=VERIFY_SSL,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    if not response.ok:
        raise RuntimeError(
            f"Archer SOAP search failed. Status: {response.status_code}. "
            f"Response preview: {response.text[:2000]}. "
            f"Search XML: {search_xml}"
        )

    return response.text

def find_matching_content_id_in_execute_search_result(
    soap_text: str,
    finding_id_field_id: int,
    finding_id: str,
) -> int:
    target_tracking_number = finding_id_to_tracking_number(finding_id)

    root = ET.fromstring(soap_text)

    result_node = root.find(
        ".//{http://archer-tech.com/webservices/}ExecuteSearchResult"
    )

    if result_node is None or not result_node.text:
        raise RuntimeError(f"No ExecuteSearchResult returned for {finding_id}")

    inner_xml = html.unescape(result_node.text)

    if not inner_xml.strip():
        raise RuntimeError(f"Empty ExecuteSearchResult returned for {finding_id}")

    records_root = ET.fromstring(inner_xml)

    debug_records: List[Dict[str, Any]] = []

    for record in records_root.iter():
        tag_lower = record.tag.lower()

        if not tag_lower.endswith("record"):
            continue

        attrs = {k.lower(): v for k, v in record.attrib.items()}

        content_id = None
        for key in ["contentid", "content_id", "id"]:
            value = attrs.get(key)
            if value and str(value).isdigit():
                maybe_id = int(value)
                if maybe_id > 10000:
                    content_id = maybe_id
                    break

        if not content_id:
            continue

        finding_value = ""

        for field in record.iter():
            if not field.tag.lower().endswith("field"):
                continue

            field_attrs = {k.lower(): v for k, v in field.attrib.items()}
            field_id_raw = (
                field_attrs.get("id")
                or field_attrs.get("fieldid")
                or field_attrs.get("field_id")
            )

            if str(field_id_raw) == str(finding_id_field_id):
                finding_value = clean_html_text(field.text or "")
                break

        debug_records.append(
            {
                "content_id": content_id,
                "finding_value": finding_value,
            }
        )

        if finding_value.strip() == target_tracking_number:
            return content_id

    raise RuntimeError(
        f"Search returned records, but none matched {finding_id}. "
        f"Expected field {finding_id_field_id} value '{target_tracking_number}'. "
        f"Records seen: {debug_records[:10]}. "
        f"Raw inner XML preview: {inner_xml[:2000]}"
    )


def find_archer_content_id_by_finding_id(
    token: str,
    application_id: int,
    finding_id_field_id: int,
    finding_id: str,
) -> int:
    soap_text = archer_soap_search_records(
        token=token,
        application_id=application_id,
        finding_id_field_id=finding_id_field_id,
        finding_id=finding_id,
    )

    return find_matching_content_id_in_execute_search_result(
        soap_text=soap_text,
        finding_id_field_id=finding_id_field_id,
        finding_id=finding_id,
    )


# ============================================================
# Reverse sync payload builder
# ============================================================

def normalize_servicenow_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = unwrap_payload(payload)

    description = safe_str(
        flex_get(
            payload,
            "description",
            "Description",
            "comments",
            "Comments",
            "work_notes",
            "Work notes",
            "workNotes",
        )
    )

    short_description = safe_str(
        flex_get(
            payload,
            "short_description",
            "Short description",
            "shortDescription",
            "title",
            "Title",
        )
    )

    archer_finding_id = (
        safe_str(
            flex_get(
                payload,
                "archer_finding_id",
                "archerFindingId",
                "finding_id",
                "Finding ID",
                "fnd_id",
                "FND ID",
            )
        )
        or extract_archer_id_from_text(description)
        or extract_archer_id_from_text(short_description)
    )

    archer_content_id = (
        safe_int(
            flex_get(
                payload,
                "archer_content_id",
                "archerContentId",
                "content_id",
                "contentId",
                "Content ID",
            )
        )
        or extract_archer_content_id_from_text(description)
        or extract_archer_content_id_from_text(short_description)
    )

    if not archer_finding_id:
        raise ValueError(
            "Could not find Archer Finding ID. "
            "Expected direct field like finding_id / archer_finding_id "
            "or marker like [ARCHER_ID:FND-1635]. "
            f"Received keys: {list(payload.keys())}"
        )

    if not archer_finding_id.upper().startswith("FND-"):
        archer_finding_id = f"FND-{archer_finding_id}"

    return {
        "archer_finding_id": archer_finding_id.upper(),
        "archer_content_id": archer_content_id,
        "short_description": short_description,
        "description": description,
        "state": safe_str(flex_get(payload, "state", "State", "status", "Status")),
        "priority": safe_str(flex_get(payload, "priority", "Priority")),
        "raw": payload,
    }


def build_archer_reverse_payload(sn_data: Dict[str, Any]) -> Dict[str, Any]:
    finding_text = extract_finding_section(sn_data["description"])

    if not finding_text:
        raise ValueError("Finding section is empty. Nothing to sync back to Archer.")

    return {
        "finding_id": sn_data["archer_finding_id"],
        "content_id": sn_data.get("archer_content_id"),
        "fields_to_update": {
            "Finding": finding_text,
        },
        "raw_servicenow": sn_data,
    }


def update_archer_record_real(archer_payload: Dict[str, Any]) -> Dict[str, Any]:
    token = archer_login()

    field_ids = {
        "Finding ID": ARCHER_FINDING_ID_FIELD_ID,
        "Finding": ARCHER_FINDING_TEXT_FIELD_ID,
    }

    content_id = safe_int(archer_payload.get("content_id"))

    content_id_source = "servicenow_payload_or_marker"

    if not content_id:
        content_id_source = "verified_archer_search"
        content_id = find_archer_content_id_by_finding_id(
            token=token,
            application_id=FINDINGS_APPLICATION_ID,
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
        level_id=FINDINGS_LEVEL_ID,
    )

    if not update_result.get("success"):
        raise RuntimeError(f"Archer content update failed: {update_result}")

    return {
        "dry_run": False,
        "message": "Archer update completed.",
        "finding_id": archer_payload["finding_id"],
        "archer_content_id": content_id,
        "content_id_source": content_id_source,
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
            "hosting": "Render",
            "endpoints": [
                "/health",
                "/archer-to-servicenow",
                "/servicenow-to-archer",
                "/debug-env",
                "/debug-servicenow",
                "/debug-archer-login",
                "/debug-archer-fields",
                "/debug-find-content/FND-1635",
                "/debug-echo",
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
        payload = parse_inbound_request()

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
                    "archer_content_id": sn_payload["archer_content_id"],
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
                "archer_content_id": sn_payload["archer_content_id"],
                "servicenow_sys_id": created_record.get("sys_id"),
                "servicenow_response": result,
            }
        ), 201

    except requests.HTTPError as exc:
        resp = exc.response
        return jsonify(
            {
                "ok": False,
                "error": "ServiceNow HTTP error",
                "status_code": resp.status_code if resp else None,
                "response": resp.text[:1000] if resp else None,
                "traceback": traceback.format_exc(),
            }
        ), 500

    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }
        ), 500


@app.route("/servicenow-to-archer", methods=["POST"])
def servicenow_to_archer():
    try:
        payload = parse_inbound_request()

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
        resp = exc.response
        return jsonify(
            {
                "ok": False,
                "error": "HTTP error during ServiceNow to Archer sync",
                "status_code": resp.status_code if resp else None,
                "response": resp.text[:1000] if resp else None,
                "traceback": traceback.format_exc(),
            }
        ), 500

    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }
        ), 500


# ============================================================
# Debug routes
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
        "FINDINGS_APPLICATION_ID",
        "FINDINGS_LEVEL_ID",
        "ARCHER_FINDING_ID_FIELD_ID",
        "ARCHER_FINDING_TEXT_FIELD_ID",
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
        resp = requests.get(
            servicenow_table_url(),
            headers=servicenow_headers(),
            auth=(SERVICENOW_USERNAME, SERVICENOW_PASSWORD),
            params={"sysparm_limit": "1"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        return jsonify(
            {
                "ok": resp.ok,
                "status_code": resp.status_code,
                "preview": resp.text[:500],
            }
        ), resp.status_code

    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": str(exc),
                "traceback": traceback.format_exc(),
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
                "traceback": traceback.format_exc(),
            }
        ), 500


@app.route("/debug-archer-fields", methods=["GET"])
def debug_archer_fields():
    return jsonify(
        {
            "ok": True,
            "source": "direct env field IDs",
            "application_id": FINDINGS_APPLICATION_ID,
            "level_id": FINDINGS_LEVEL_ID,
            "field_ids": {
                "Finding ID": ARCHER_FINDING_ID_FIELD_ID,
                "Finding": ARCHER_FINDING_TEXT_FIELD_ID,
            },
        }
    ), 200


@app.route("/debug-find-content/<finding_id>", methods=["GET"])
def debug_find_content(finding_id: str):
    try:
        token = archer_login()

        content_id = find_archer_content_id_by_finding_id(
            token=token,
            application_id=FINDINGS_APPLICATION_ID,
            finding_id_field_id=ARCHER_FINDING_ID_FIELD_ID,
            finding_id=finding_id,
        )

        return jsonify(
            {
                "ok": True,
                "finding_id": finding_id,
                "application_id": FINDINGS_APPLICATION_ID,
                "finding_id_field_id": ARCHER_FINDING_ID_FIELD_ID,
                "content_id": content_id,
            }
        ), 200

    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }
        ), 500


@app.route("/debug-echo", methods=["POST"])
def debug_echo():
    try:
        payload = parse_inbound_request()

        return jsonify(
            {
                "ok": True,
                "parsed_payload": payload,
                "content_type": request.content_type,
                "headers": {
                    key: value
                    for key, value in request.headers.items()
                    if key.lower() not in {"authorization", "cookie"}
                },
            }
        ), 200

    except Exception as exc:
        return jsonify(
            {
                "ok": False,
                "error": str(exc),
                "content_type": request.content_type,
                "raw_body": request.get_data(as_text=True)[:1000],
                "traceback": traceback.format_exc(),
            }
        ), 400


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    app.run(
        host=get_env_optional("FLASK_HOST", "0.0.0.0"),
        port=get_env_int("PORT", get_env_int("FLASK_PORT", 5001)),
        debug=get_env_bool("FLASK_DEBUG", False),
    )