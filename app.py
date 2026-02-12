"""
AI-Powered Log Harmonizer & Regex Generator
=============================================
Two-phase architecture for massive-scale log parsing:

Phase 1 — LEARN: Upload a small sample of files. AI discovers patterns
          and generates regex. Patterns are saved to a reusable library.

Phase 2 — APPLY: Upload millions of files. The app matches fingerprints
          to the library and parses locally with regex. ZERO API calls.

Only calls AI for genuinely new/unrecognized patterns.
"""

import streamlit as st
import pandas as pd
import json
import re
import io
import hashlib
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Generator

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Log Harmonizer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """<system_prompt>
You are a Security Data Engineer. Given a raw log line (which may be a multi-line
entry joined with '  |  ' separators):
1. Extract ALL meaningful variables into a valid JSON object — including fields from
   continuation blocks like Application Information, Network Information, Filter Information, etc.
2. Clean and flatten the "message" field. Remove extraneous line breaks and whitespace.
3. Normalize any timestamps to ISO-8601 format (YYYY-MM-DDTHH:MM:SS±HH:MM).
4. Provide a high-performance PCRE Regex pattern to parse this specific log format.
   - Use named capture groups: (?P<field_name>...)
   - The regex MUST match the original raw line exactly.
5. Output ONLY valid JSON in this exact schema — no markdown, no explanation:
{
  "parsed_data": {
    "timestamp": "ISO-8601 or null",
    "source": "source system or null",
    "event_id": "event id or null",
    "severity": "severity level or null",
    "message": "cleaned message text",
    "additional_fields": {
      "process_id": "...",
      "application_name": "...",
      "direction": "...",
      "source_address": "...",
      "source_port": "...",
      "destination_address": "...",
      "destination_port": "...",
      "protocol": "...",
      "filter_id": "...",
      "layer_name": "...",
      "...": "include ALL fields found in the log"
    }
  },
  "generated_regex": "^(?P<timestamp>...) ...",
  "confidence_score": 0.95
}

IMPORTANT: Extract EVERY key-value pair found in the log, especially from structured
blocks like "Network Information:", "Application Information:", "Filter Information:", etc.
Do NOT skip any fields. If a field has no value, set it to null.
</system_prompt>"""

BATCH_SYSTEM_PROMPT = """<system_prompt>
You are a Security Data Engineer. You will receive MULTIPLE log pattern groups.
Log entries may be multi-line, joined with '  |  ' separators.
For EACH group, extract ALL fields (including from continuation blocks like
Network Information, Application Information, Filter Information), normalize
timestamps to ISO-8601, and generate a PCRE regex.

Output ONLY a valid JSON array — no markdown, no explanation. Each element must follow this schema:
{
  "group_id": "the group ID provided",
  "parsed_data": {
    "timestamp": "ISO-8601 or null",
    "source": "source system or null",
    "event_id": "event id or null",
    "severity": "severity level or null",
    "message": "cleaned message text",
    "additional_fields": {"...include ALL fields found..."}
  },
  "generated_regex": "^(?P<timestamp>...) ...",
  "confidence_score": 0.95
}
</system_prompt>"""

MODELS = {
    "Haiku 4.5 (fast, cheap)": "claude-haiku-4-5-20251001",
    "Sonnet 4 (balanced)": "claude-sonnet-4-20250514",
}

SIEM_FORMATS = {
    "Splunk (Regex)": "regex",
    "Elastic (Grok)": "grok",
    "Sentinel (KQL)": "kql",
    "FortiSIEM (XML Parser)": "fortisiem",
}

# Patterns used by the anonymization mode
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
USERNAME_PATTERN = re.compile(
    r"(?:[Uu]ser(?:name)?[=: ]+)([\w.\-\\]+)"
)


# =========================================================================
# 1. ANONYMIZATION HELPERS
# =========================================================================
def anonymize_line(line: str) -> tuple[str, dict]:
    """Mask IPs, emails, and usernames. Return masked line + mapping."""
    mapping: dict[str, str] = {}
    counter = {"ip": 0, "email": 0, "user": 0}

    def _replace_ip(m: re.Match) -> str:
        token = f"<MASKED_IP_{counter['ip']}>"
        mapping[token] = m.group(0)
        counter["ip"] += 1
        return token

    def _replace_email(m: re.Match) -> str:
        token = f"<MASKED_EMAIL_{counter['email']}>"
        mapping[token] = m.group(0)
        counter["email"] += 1
        return token

    def _replace_user(m: re.Match) -> str:
        token = f"<MASKED_USER_{counter['user']}>"
        mapping[token] = m.group(1)
        counter["user"] += 1
        return m.group(0).replace(m.group(1), token)

    line = IP_PATTERN.sub(_replace_ip, line)
    line = EMAIL_PATTERN.sub(_replace_email, line)
    line = USERNAME_PATTERN.sub(_replace_user, line)
    return line, mapping


def deanonymize_result(result: dict, mapping: dict) -> dict:
    """Restore original values in a parsed result dict."""
    if not mapping:
        return result
    text = json.dumps(result)
    for token, original in mapping.items():
        text = text.replace(token, original)
    return json.loads(text)


# =========================================================================
# 2. MULTI-LINE REASSEMBLY & FINGERPRINTING
# =========================================================================
_NEW_ENTRY_PATTERNS = [
    re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}"),
    re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
    re.compile(r"^CEF:\d"),
    re.compile(r"^<\d+>\d?\s*\d{4}-"),
    re.compile(r"^<\d+>"),
    re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}\s+\d{2}:\d{2}:\d{2}\t"),
    re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+"),
]


def _is_new_entry(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    return any(p.match(stripped) for p in _NEW_ENTRY_PATTERNS)


def reassemble_multiline(raw_lines: list[str]) -> list[str]:
    """Join continuation lines back to their parent log entry."""
    if not raw_lines:
        return []
    entries: list[str] = []
    current: list[str] = []
    for line in raw_lines:
        stripped = line.strip()
        if not stripped:
            continue
        if _is_new_entry(stripped):
            if current:
                entries.append("  |  ".join(current))
            current = [stripped]
        else:
            if current:
                current.append(stripped)
            else:
                current = [stripped]
    if current:
        entries.append("  |  ".join(current))
    return entries


def _tokenize(line: str) -> list[str]:
    """Split a log line into tokens, replacing variable-looking parts."""
    header = line.split("  |  ")[0] if "  |  " in line else line
    tokens = header.strip().split()
    normalized: list[str] = []
    for t in tokens:
        if re.fullmatch(r"\d+", t):
            normalized.append("<NUM>")
        elif re.fullmatch(r"[\da-fA-F]{8,}", t):
            normalized.append("<HEX>")
        elif IP_PATTERN.fullmatch(t):
            normalized.append("<IP>")
        elif re.fullmatch(r"\d{4}[-/]\d{2}[-/]\d{2}", t):
            normalized.append("<DATE>")
        elif re.fullmatch(r"\d{2}:\d{2}:\d{2}(?:\.\d+)?", t):
            normalized.append("<TIME>")
        else:
            normalized.append(t)
    return normalized


def fingerprint(line: str) -> str:
    tokens = _tokenize(line)
    skeleton = " ".join(tokens)
    return hashlib.md5(skeleton.encode()).hexdigest()


def cluster_logs(lines: list[str]) -> dict[str, list[str]]:
    clusters: dict[str, list[str]] = defaultdict(list)
    for line in lines:
        if not line.strip():
            continue
        fp = fingerprint(line)
        clusters[fp].append(line)
    return dict(clusters)


# =========================================================================
# 3. FILE INGESTION (streaming / chunked)
# =========================================================================
def stream_lines(uploaded_file, chunk_size: int = 1024 * 64) -> Generator[str, None, None]:
    uploaded_file.seek(0)
    buffer = ""
    while True:
        chunk = uploaded_file.read(chunk_size)
        if isinstance(chunk, bytes):
            chunk = chunk.decode("utf-8", errors="replace")
        if not chunk:
            break
        buffer += chunk
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            stripped = line.strip()
            if stripped:
                yield stripped
    if buffer.strip():
        yield buffer.strip()


def quick_scan_file(uploaded_file, max_lines: int = 20) -> list[str]:
    """Read only the first N lines from a file — for fast format discovery."""
    uploaded_file.seek(0)
    lines: list[str] = []
    buffer = ""
    chunk_size = 1024 * 16  # small reads since we only need a few lines
    while len(lines) < max_lines:
        chunk = uploaded_file.read(chunk_size)
        if isinstance(chunk, bytes):
            chunk = chunk.decode("utf-8", errors="replace")
        if not chunk:
            break
        buffer += chunk
        while "\n" in buffer and len(lines) < max_lines:
            line, buffer = buffer.split("\n", 1)
            stripped = line.strip()
            if stripped:
                lines.append(stripped)
    return lines


def discover_formats(
    files: list,
    scan_lines: int = 20,
) -> tuple[dict[str, dict], int, int]:
    """
    Quick-scan all files to discover unique log formats.
    Only reads the first N lines per file — very fast even for millions of files.

    Returns:
        format_map: {fingerprint: {"sample": str, "files": [filenames], "count": int}}
        total_files: number of files scanned
        total_lines_sampled: total lines read across all files
    """
    format_map: dict[str, dict] = {}
    total_lines = 0

    for uf in files:
        sample_lines = quick_scan_file(uf, max_lines=scan_lines)
        total_lines += len(sample_lines)

        # Reassemble multi-line entries from sample
        entries = reassemble_multiline(sample_lines)

        for entry in entries:
            fp = fingerprint(entry)
            if fp not in format_map:
                format_map[fp] = {
                    "sample": entry,
                    "files": [],
                    "count": 0,
                }
            if uf.name not in format_map[fp]["files"]:
                format_map[fp]["files"].append(uf.name)
            format_map[fp]["count"] += 1

    return format_map, len(files), total_lines


# =========================================================================
# 4. PATTERN LIBRARY — learn once, apply forever
# =========================================================================
def _empty_library() -> dict:
    """Return a fresh empty pattern library structure."""
    return {
        "version": 2,
        "created": datetime.now().isoformat(),
        "patterns": {},   # fingerprint -> pattern entry
    }


def _add_to_library(library: dict, fp: str, ai_result: dict, sample: str) -> None:
    """Add a learned pattern to the library."""
    library["patterns"][fp] = {
        "regex": ai_result.get("generated_regex", ""),
        "field_names": list((ai_result.get("parsed_data") or {}).keys()),
        "parsed_template": ai_result.get("parsed_data", {}),
        "confidence": ai_result.get("confidence_score", 0),
        "sample": sample[:500],
        "learned_at": datetime.now().isoformat(),
        # Store SIEM-specific outputs if present
        "grok_pattern": ai_result.get("grok_pattern"),
        "kql_parse": ai_result.get("kql_parse"),
        "fortisiem_parser": ai_result.get("fortisiem_parser"),
    }


def apply_regex_locally(regex_str: str, line: str) -> dict | None:
    """Try to parse a log line using a compiled regex. Returns named groups or None."""
    try:
        m = re.match(regex_str, line)
        if m:
            return {k: v for k, v in m.groupdict().items() if v is not None}
    except re.error:
        pass
    return None


def apply_library_to_entries(
    library: dict,
    clusters: dict[str, list[str]],
    progress_callback=None,
) -> tuple[list[dict], list[dict], list[str], dict[str, list[str]]]:
    """
    Parse all entries locally using the pattern library. Zero API calls.
    Returns (results, regex_manifest, warnings, unmatched_clusters).
    """
    results: list[dict] = []
    regex_manifest: list[dict] = []
    warnings: list[str] = []
    unmatched: dict[str, list[str]] = {}
    patterns = library.get("patterns", {})

    cluster_items = list(clusters.items())
    total = len(cluster_items)

    for idx, (fp, lines) in enumerate(cluster_items):
        if progress_callback:
            progress_callback(idx + 1, total)

        pattern_entry = patterns.get(fp)

        if pattern_entry is None:
            unmatched[fp] = lines
            continue

        regex_str = pattern_entry.get("regex", "")
        template = pattern_entry.get("parsed_template", {})

        # Try regex-based extraction on first line to validate
        regex_parsed = apply_regex_locally(regex_str, lines[0]) if regex_str else None

        # Build manifest entry
        manifest_entry = {
            "cluster_id": fp[:12],
            "sample_count": len(lines),
            "regex": regex_str,
            "confidence": pattern_entry.get("confidence", 0),
            "source": "library",
        }
        if pattern_entry.get("grok_pattern"):
            manifest_entry["grok_pattern"] = pattern_entry["grok_pattern"]
        if pattern_entry.get("kql_parse"):
            manifest_entry["kql_parse"] = pattern_entry["kql_parse"]
        if pattern_entry.get("fortisiem_parser"):
            manifest_entry["fortisiem_parser"] = pattern_entry["fortisiem_parser"]
        regex_manifest.append(manifest_entry)

        for line in lines:
            if regex_parsed is not None:
                # Use regex extraction for each line
                parsed = apply_regex_locally(regex_str, line)
                if parsed:
                    row = parsed.copy()
                else:
                    # Regex didn't match this line — fall back to template
                    row = flatten_parsed(template)
            else:
                # Regex doesn't work — use the AI-generated template fields
                row = flatten_parsed(template)

            row["_raw"] = line
            row["_cluster_id"] = fp[:12]
            row["_confidence"] = pattern_entry.get("confidence", 0)
            row["_source"] = "library"
            results.append(row)

    if unmatched:
        warnings.append(
            f"{len(unmatched)} cluster(s) not in library ({sum(len(v) for v in unmatched.values()):,} lines). "
            f"Use Learn mode to add them."
        )

    return results, regex_manifest, warnings, unmatched


# =========================================================================
# 5. AI INTEGRATION (Anthropic Claude)
# =========================================================================
def _get_client(api_key: str):
    import anthropic
    return anthropic.Anthropic(api_key=api_key)


def _parse_json_response(text: str) -> dict | list | None:
    text = text.strip()
    json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if json_match:
        text = json_match.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for opener, closer in [("[", "]"), ("{", "}")]:
        try:
            start = text.index(opener)
            end = text.rindex(closer) + 1
            return json.loads(text[start:end])
        except (ValueError, json.JSONDecodeError):
            continue
    return None


def call_claude_single(client, model, sample_lines, siem_format):
    siem_extra = ""
    if siem_format == "grok":
        siem_extra = '\nAlso include a "grok_pattern" in your JSON output.'
    elif siem_format == "kql":
        siem_extra = '\nAlso include a "kql_parse" in your JSON output.'
    elif siem_format == "fortisiem":
        siem_extra = (
            '\nAlso generate a FortiSIEM XML parser with <patternDefinitions> '
            'and <parsingInstructions>. Include as "fortisiem_parser" in your JSON.'
        )

    user_message = (
        "Analyze the following raw log sample(s). Return ONE JSON object.\n"
        f"{siem_extra}\n\n--- RAW LOG SAMPLES ---\n"
        + "\n".join(sample_lines)
    )
    try:
        response = client.messages.create(
            model=model, max_tokens=2048, system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        raw_text = response.content[0].text
        parsed = _parse_json_response(raw_text)
        if parsed is None:
            return None, f"JSON parse failed. Raw: {raw_text[:300]}"
        return parsed, None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def call_claude_batch(client, model, batch, siem_format):
    siem_extra = ""
    if siem_format == "grok":
        siem_extra = '\nFor each group, also include a "grok_pattern" field.'
    elif siem_format == "kql":
        siem_extra = '\nFor each group, also include a "kql_parse" field.'
    elif siem_format == "fortisiem":
        siem_extra = '\nFor each group, also include a "fortisiem_parser" field with a FortiSIEM XML parser pattern.'

    groups_text = ""
    for group_id, samples in batch:
        groups_text += f"\n--- GROUP {group_id} ---\n" + "\n".join(samples) + "\n"

    user_message = (
        f"Analyze each group of log samples below. Return a JSON array with one "
        f"object per group.{siem_extra}\n{groups_text}"
    )
    try:
        response = client.messages.create(
            model=model, max_tokens=4096, system=BATCH_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        raw_text = response.content[0].text
        parsed = _parse_json_response(raw_text)
        if isinstance(parsed, list):
            return {item["group_id"]: item for item in parsed if "group_id" in item}, None
        elif isinstance(parsed, dict) and "group_id" in parsed:
            return {parsed["group_id"]: parsed}, None
        return {}, f"Unexpected response format. Raw: {raw_text[:300]}"
    except Exception as e:
        return {}, f"{type(e).__name__}: {e}"


# =========================================================================
# 6. LEARN ENGINE — discover patterns via AI
# =========================================================================
def learn_patterns(
    api_key: str,
    clusters: dict[str, list[str]],
    siem_format: str,
    model: str,
    samples_per_cluster: int,
    anonymize: bool,
    max_workers: int,
    batch_size: int,
    existing_library: dict | None = None,
    progress_callback=None,
) -> tuple[dict, list[str]]:
    """
    Discover patterns via AI and return an updated pattern library.
    Skips clusters that already exist in the library.
    Returns (updated_library, errors).
    """
    library = existing_library or _empty_library()
    existing_fps = set(library.get("patterns", {}).keys())

    # Filter to only NEW clusters
    new_clusters = {fp: lines for fp, lines in clusters.items() if fp not in existing_fps}

    if not new_clusters:
        return library, ["All clusters already in library. No API calls needed."]

    client = _get_client(api_key)
    cluster_items = list(new_clusters.items())
    total = len(cluster_items)
    errors: list[str] = []

    # Prepare samples
    prepared: list[tuple[str, list[str], dict]] = []
    for fp, lines in cluster_items:
        samples = lines[:samples_per_cluster]
        anon_mapping: dict = {}
        if anonymize:
            anon_samples, combined = [], {}
            for s in samples:
                masked, mapping = anonymize_line(s)
                anon_samples.append(masked)
                combined.update(mapping)
            samples = anon_samples
            anon_mapping = combined
        prepared.append((fp, samples, anon_mapping))

    ai_results: dict[str, dict | None] = {}
    completed = 0

    if batch_size > 1 and total > 1:
        batches = [prepared[i:i + batch_size] for i in range(0, len(prepared), batch_size)]

        def _run_batch(batch_items):
            batch_input = [(fp[:12], samples) for fp, samples, _ in batch_items]
            result_dict, err = call_claude_batch(client, model, batch_input, siem_format)
            return result_dict, batch_items, err

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_run_batch, b): b for b in batches}
            for future in as_completed(futures):
                try:
                    batch_result, batch_items, err = future.result()
                    if err:
                        errors.append(f"Batch error: {err}")
                    for fp, samples, anon_mapping in batch_items:
                        result = batch_result.get(fp[:12])
                        if result and anonymize and anon_mapping:
                            result = deanonymize_result(result, anon_mapping)
                        ai_results[fp] = result
                        completed += 1
                except Exception as e:
                    errors.append(f"Thread error: {type(e).__name__}: {e}")
                if progress_callback:
                    progress_callback(min(completed, total), total)
    else:
        def _run_single(item):
            fp, samples, anon_mapping = item
            result, err = call_claude_single(client, model, samples, siem_format)
            if result and anonymize and anon_mapping:
                result = deanonymize_result(result, anon_mapping)
            return fp, result, err

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_run_single, p): p for p in prepared}
            for future in as_completed(futures):
                try:
                    fp, result, err = future.result()
                    if err:
                        errors.append(f"Cluster {fp[:8]}: {err}")
                    ai_results[fp] = result
                    completed += 1
                except Exception as e:
                    errors.append(f"Thread error: {type(e).__name__}: {e}")
                if progress_callback:
                    progress_callback(min(max(completed, 1), total), total)

    # Save learned patterns to library
    learned = 0
    for fp, lines in cluster_items:
        ai_result = ai_results.get(fp)
        if ai_result is None:
            continue
        _add_to_library(library, fp, ai_result, lines[0])
        learned += 1

    library["last_updated"] = datetime.now().isoformat()
    errors.insert(0, f"Learned {learned} new pattern(s) from {total} cluster(s).")

    return library, errors


# =========================================================================
# 7. SIEM FORMAT CONVERTERS
# =========================================================================
def regex_to_grok(regex: str) -> str:
    def _replace(m):
        name, pattern = m.group(1), m.group(2)
        grok_type = "DATA"
        if "\\d" in pattern or pattern in (r"\d+", r"[0-9]+"):
            grok_type = "INT"
        elif "TIMESTAMP" in name.upper() or "date" in name.lower():
            grok_type = "TIMESTAMP_ISO8601"
        elif "ip" in name.lower():
            grok_type = "IP"
        return f"%{{{grok_type}:{name}}}"
    return re.sub(r"\(\?P<(\w+)>(.*?)\)", _replace, regex)


def regex_to_kql(regex: str, fields: list[str]) -> str:
    placeholders = " ".join(f"*{f}:string*" for f in fields)
    return f"| parse RawLog with {placeholders}  // Adjust delimiters"


def regex_to_fortisiem(regex: str, fields: list[str]) -> str:
    forti_map = {
        "timestamp": "deviceTime", "source": "reportingIP",
        "src_ip": "srcIpAddr", "dst_ip": "destIpAddr",
        "src_port": "srcIpPort", "dst_port": "destIpPort",
        "event_id": "eventType", "severity": "eventSeverity",
        "message": "rawEventMsg", "user": "user", "username": "user",
        "action": "eventAction", "protocol": "ipProto",
        "hostname": "hostName", "process": "procName", "pid": "procId",
    }
    patterns, rules = [], []
    for f in fields:
        if f == "additional_fields":
            continue
        attr = forti_map.get(f.lower(), f)
        patterns.append(f'    <pattern name="pat_{f}"><![CDATA[<:gPatStr>]]></pattern>')
        rules.append(f'    <fieldMapping attr="{attr}" pattern="pat_{f}" group="1"/>')
    return (
        '<eventParser name="Custom-LogHarmonizer">\n'
        '  <patternDefinitions>\n' + "\n".join(patterns) + "\n"
        '  </patternDefinitions>\n'
        '  <parsingInstructions>\n' + "\n".join(rules) + "\n"
        '  </parsingInstructions>\n'
        '</eventParser>'
    )


# =========================================================================
# 8. RESULT AGGREGATION
# =========================================================================
def flatten_parsed(parsed_data: dict) -> dict:
    flat: dict = {}
    for k, v in parsed_data.items():
        if isinstance(v, dict):
            for sub_k, sub_v in v.items():
                flat[f"{k}.{sub_k}"] = sub_v
        else:
            flat[k] = v
    return flat


# =========================================================================
# 9. STREAMLIT UI
# =========================================================================
def main():
    # -- Sidebar -------------------------------------------------------
    with st.sidebar:
        st.image("https://img.icons8.com/fluency/96/parse-from-clipboard.png", width=60)
        st.title("⚙️ Settings")

        try:
            api_key = st.secrets["ANTHROPIC_API_KEY"]
        except (KeyError, FileNotFoundError):
            api_key = ""

        model_choice = st.selectbox(
            "AI Model", options=list(MODELS.keys()), index=0,
            help="Haiku = ~3× faster & cheaper. Sonnet = higher accuracy.",
        )
        model = MODELS[model_choice]

        siem_choice = st.selectbox(
            "SIEM Output Format", options=list(SIEM_FORMATS.keys()), index=0,
        )
        siem_format = SIEM_FORMATS[siem_choice]

        anonymize = st.toggle("🔒 Anonymization Mode", value=False,
            help="Mask IPs, emails, and usernames before sending to AI.")

        st.divider()
        st.markdown("**⚡ Performance**")

        samples_per_cluster = st.slider("Samples per cluster", 1, 5, 2)
        max_workers = st.slider("Parallel workers", 1, 8, 4)
        batch_size = st.slider("Clusters per API call", 1, 10, 5)

        st.divider()

        # -- Pattern Library Management --
        st.markdown("**📚 Pattern Library**")
        lib = st.session_state.get("pattern_library")
        if lib:
            n_patterns = len(lib.get("patterns", {}))
            st.success(f"{n_patterns} pattern(s) loaded")
        else:
            st.caption("No library loaded")

        uploaded_lib = st.file_uploader(
            "Import library (.json)", type=["json"], key="lib_upload",
        )
        if uploaded_lib:
            try:
                lib_data = json.load(uploaded_lib)
                if "patterns" in lib_data:
                    st.session_state["pattern_library"] = lib_data
                    st.success(f"Imported {len(lib_data['patterns'])} patterns!")
                    st.rerun()
                else:
                    st.error("Invalid library file — missing 'patterns' key.")
            except json.JSONDecodeError:
                st.error("Invalid JSON file.")

        if lib:
            lib_json = json.dumps(lib, indent=2, default=str)
            st.download_button(
                "⬇️ Export Library",
                data=lib_json,
                file_name=f"pattern_library_{datetime.now():%Y%m%d_%H%M%S}.json",
                mime="application/json",
                use_container_width=True,
            )
            if st.button("🗑️ Clear Library", use_container_width=True):
                st.session_state.pop("pattern_library", None)
                st.rerun()

        st.divider()
        st.caption("Built for SOC analysts & security engineers.")

    # -- Header --------------------------------------------------------
    st.title("🔍 Log Harmonizer & Regex Generator")

    # -- Mode Tabs -----------------------------------------------------
    tab_auto, tab_discover, tab_learn, tab_apply = st.tabs([
        "🚀 Auto Pipeline",
        "🔎 Discover Formats",
        "🧠 Learn Patterns (uses AI)",
        "⚡ Apply & Parse (no AI)",
    ])

    # ==================================================================
    # AUTO PIPELINE — dump files, get results, minimal AI
    # ==================================================================
    with tab_auto:
        st.markdown(
            "**Just upload everything.** The app auto-detects known patterns "
            "(parsed locally, free) and calls AI only for new ones. "
            "Your Pattern Library grows automatically."
        )

        auto_files = st.file_uploader(
            "Upload log files (any type, any mix)",
            type=["txt", "log", "csv"],
            accept_multiple_files=True,
            key="auto_files",
        )

        if not auto_files:
            st.info("👆 Dump any log files here — the pipeline handles the rest.")

        elif not api_key:
            st.warning("API key not found. Add `ANTHROPIC_API_KEY` to Streamlit secrets.")

        else:
            # Ingest everything
            auto_raw: list[str] = []
            for uf in auto_files:
                auto_raw.extend(stream_lines(uf))
            auto_entries = reassemble_multiline(auto_raw)
            auto_clusters = cluster_logs(auto_entries)

            lib = st.session_state.get("pattern_library", _empty_library())
            lib_fps = set(lib.get("patterns", {}).keys())

            known_fps = set(auto_clusters.keys()) & lib_fps
            new_fps = set(auto_clusters.keys()) - lib_fps
            known_lines = sum(len(auto_clusters[fp]) for fp in known_fps)
            new_lines = sum(len(auto_clusters[fp]) for fp in new_fps)
            est_calls = max(1, -(-len(new_fps) // batch_size)) if new_fps else 0

            # Clear stale results on file change
            auto_sig = hashlib.md5(
                str(len(auto_raw)).encode() + str(len(auto_entries)).encode()
            ).hexdigest()
            if st.session_state.get("_auto_sig") != auto_sig:
                st.session_state.pop("auto_results", None)
                st.session_state["_auto_sig"] = auto_sig

            # Stats dashboard
            col1, col2, col3, col4, col5 = st.columns(5)
            col1.metric("Log Entries", f"{len(auto_entries):,}")
            col2.metric("Unique Patterns", len(auto_clusters))
            col3.metric("✅ Known (free)", f"{known_lines:,}")
            col4.metric("🆕 New (AI needed)", f"{new_lines:,}")
            col5.metric("Est. API Calls", est_calls)

            if not new_fps:
                st.success(
                    f"All {len(auto_clusters)} pattern(s) already in library — "
                    f"**zero API calls** needed!"
                )

            if st.button("🚀 Run Pipeline", type="primary", use_container_width=True):
                start_time = time.time()
                all_messages: list[str] = []

                # Step 1: Learn new patterns if any exist
                if new_fps:
                    progress = st.progress(0, text="Step 1/2 — Learning new patterns…")

                    def _auto_learn(done, total):
                        progress.progress(
                            done / total,
                            text=f"Step 1/2 — Learning {done}/{total} new patterns…",
                        )

                    new_clusters_only = {fp: auto_clusters[fp] for fp in new_fps}
                    updated_lib, learn_msgs = learn_patterns(
                        api_key=api_key,
                        clusters=new_clusters_only,
                        siem_format=siem_format,
                        model=model,
                        samples_per_cluster=samples_per_cluster,
                        anonymize=anonymize,
                        max_workers=max_workers,
                        batch_size=batch_size,
                        existing_library=lib,
                        progress_callback=_auto_learn,
                    )
                    st.session_state["pattern_library"] = updated_lib
                    lib = updated_lib
                    all_messages.extend(learn_msgs)
                    progress.empty()

                # Step 2: Parse ALL entries with the (now-updated) library
                step_label = "Step 2/2" if new_fps else "Parsing"
                progress = st.progress(0, text=f"{step_label} — Parsing locally…")

                def _auto_apply(done, total):
                    progress.progress(
                        done / total,
                        text=f"{step_label} — {done}/{total} clusters…",
                    )

                results, regex_manifest, warnings, unmatched = apply_library_to_entries(
                    library=lib,
                    clusters=auto_clusters,
                    progress_callback=_auto_apply,
                )
                all_messages.extend(warnings)
                elapsed = time.time() - start_time
                progress.empty()

                for msg in all_messages:
                    if "error" in msg.lower():
                        st.error(msg)
                    elif "not in library" in msg.lower():
                        st.warning(msg)
                    else:
                        st.success(msg)

                if not results:
                    st.error("No results produced. Check API key and log formats.")
                    st.stop()

                actual_calls = est_calls if new_fps else 0
                st.toast(
                    f"Parsed {len(results):,} entries in {elapsed:.1f}s "
                    f"({actual_calls} API calls)",
                    icon="🚀",
                )

                st.session_state["auto_results"] = results
                st.session_state["auto_manifest"] = regex_manifest
                st.session_state["auto_elapsed"] = elapsed
                st.session_state["auto_api_calls"] = actual_calls
                st.rerun()

            # -- Display results --
            if "auto_results" not in st.session_state:
                st.stop()

            results = st.session_state["auto_results"]
            regex_manifest = st.session_state.get("auto_manifest", [])
            elapsed = st.session_state.get("auto_elapsed", 0)
            actual_calls = st.session_state.get("auto_api_calls", 0)

            st.divider()
            col_m1, col_m2, col_m3, col_m4 = st.columns(4)
            col_m1.metric("Parsed Lines", f"{len(results):,}")
            col_m2.metric("Pattern Classes", len(regex_manifest))
            col_m3.metric("Processing Time", f"{elapsed:.1f}s")
            col_m4.metric("API Calls Used", actual_calls)

            st.subheader("📊 Parsed Results")
            df = pd.DataFrame(results)
            col_order = ["_raw", "_cluster_id", "_confidence", "_source"] + [
                c for c in df.columns if not c.startswith("_")
            ]
            df = df[[c for c in col_order if c in df.columns]]

            tab_table, tab_raw_view = st.tabs(["Structured Table", "Raw vs. Parsed"])
            with tab_table:
                st.dataframe(df, use_container_width=True, height=400)
            with tab_raw_view:
                if results:
                    idx = st.slider("Select row", 0, len(results) - 1, 0, key="auto_row")
                    row = results[idx]
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown("**Raw Log**")
                        st.code(row.get("_raw", "").replace("  |  ", "\n    "), language="log")
                    with c2:
                        st.markdown("**Parsed JSON**")
                        st.json({k: v for k, v in row.items() if not k.startswith("_")})

            st.divider()
            st.subheader("🧩 Regex / SIEM Manifest")
            for entry in regex_manifest:
                with st.expander(
                    f"Cluster `{entry['cluster_id']}` — {entry['sample_count']} lines "
                    f"({entry.get('confidence', 0):.0%}) — {entry.get('source', 'ai')}"
                ):
                    st.code(entry.get("regex", ""), language="regex")
                    for key, label, lang in [
                        ("grok_pattern", "Grok Pattern", None),
                        ("kql_parse", "KQL Parse", "kql"),
                        ("fortisiem_parser", "FortiSIEM Parser", "xml"),
                    ]:
                        if key in entry:
                            st.markdown(f"**{label}**")
                            st.code(entry[key], language=lang)

            st.divider()
            st.subheader("📦 Export")
            col_csv, col_regex, col_json = st.columns(3)
            with col_csv:
                csv_buf = io.StringIO()
                df.to_csv(csv_buf, index=False)
                st.download_button(
                    "⬇️ Master CSV", data=csv_buf.getvalue(),
                    file_name=f"harmonized_{datetime.now():%Y%m%d_%H%M%S}.csv",
                    mime="text/csv", use_container_width=True,
                )
            with col_regex:
                st.download_button(
                    "⬇️ Regex Manifest",
                    data=json.dumps(regex_manifest, indent=2),
                    file_name=f"regex_manifest_{datetime.now():%Y%m%d_%H%M%S}.json",
                    mime="application/json", use_container_width=True,
                )
            with col_json:
                st.download_button(
                    "⬇️ Full Parsed JSON",
                    data=json.dumps(results, indent=2, default=str),
                    file_name=f"parsed_logs_{datetime.now():%Y%m%d_%H%M%S}.json",
                    mime="application/json", use_container_width=True,
                )

    # ==================================================================
    # DISCOVER TAB — fast scan to find unique formats across all files
    # ==================================================================
    with tab_discover:
        st.markdown(
            "**Dump all your files here** — even millions. The app reads only the "
            "first ~20 lines per file to fingerprint the log format. "
            "It then tells you exactly how many unique formats exist and which "
            "ones need to be learned."
        )

        discover_files = st.file_uploader(
            "Upload ALL log files (fast scan — reads first 20 lines per file)",
            type=["txt", "log", "csv"],
            accept_multiple_files=True,
            key="discover_files",
        )

        if not discover_files:
            st.info("👆 Upload files to discover log formats.")
        else:
            scan_depth = st.slider(
                "Lines to scan per file", 10, 100, 20, key="scan_depth",
                help="More lines = better discovery but slower scan.",
            )

            if st.button("🔎 Scan Files", type="primary", use_container_width=True):
                with st.spinner(f"Scanning {len(discover_files):,} files…"):
                    start = time.time()
                    fmt_map, n_files, n_lines = discover_formats(
                        discover_files, scan_lines=scan_depth,
                    )
                    elapsed = time.time() - start

                st.session_state["discover_results"] = fmt_map
                st.session_state["discover_stats"] = (n_files, n_lines, elapsed)
                st.rerun()

            if "discover_results" in st.session_state:
                fmt_map = st.session_state["discover_results"]
                n_files, n_lines, elapsed = st.session_state["discover_stats"]

                lib = st.session_state.get("pattern_library", _empty_library())
                lib_fps = set(lib.get("patterns", {}).keys())
                known_fps = set(fmt_map.keys()) & lib_fps
                new_fps = set(fmt_map.keys()) - lib_fps

                st.divider()
                col_d1, col_d2, col_d3, col_d4, col_d5 = st.columns(5)
                col_d1.metric("Files Scanned", f"{n_files:,}")
                col_d2.metric("Lines Sampled", f"{n_lines:,}")
                col_d3.metric("Unique Formats", len(fmt_map))
                col_d4.metric("✅ Already in Library", len(known_fps))
                col_d5.metric("🆕 Need Learning", len(new_fps))

                st.caption(f"Scan completed in {elapsed:.1f}s")

                if not new_fps:
                    st.success(
                        "All discovered formats are already in your Pattern Library. "
                        "Go straight to the **Apply & Parse** tab!"
                    )
                else:
                    est_calls = max(1, -(-len(new_fps) // batch_size))
                    st.info(
                        f"Only **{len(new_fps)}** new format(s) to learn — "
                        f"~**{est_calls}** API call(s). "
                        f"Go to the **Learn Patterns** tab to teach them."
                    )

                # Show discovered formats
                st.subheader("Discovered Formats")
                for fp, info in sorted(
                    fmt_map.items(),
                    key=lambda x: x[1]["count"],
                    reverse=True,
                ):
                    status = "✅ In Library" if fp in lib_fps else "🆕 New"
                    n_src_files = len(info['files'])
                    file_list = ", ".join(info['files'][:5])
                    if n_src_files > 5:
                        file_list += f", … (+{n_src_files - 5} more)"

                    with st.expander(
                        f"{status} | Pattern `{fp[:12]}` — "
                        f"found in {n_src_files} file(s), {info['count']} sample(s)"
                    ):
                        st.markdown(f"**Source files:** {file_list}")
                        st.markdown("**Sample entry:**")
                        display = info["sample"].replace("  |  ", "\n    ")
                        st.code(display[:500], language="log")

    # ==================================================================
    # LEARN TAB
    # ==================================================================
    with tab_learn:
        st.markdown(
            "Upload log files with **new formats** to teach the AI. "
            "It skips patterns already in your library — only new ones cost API calls. "
            "You can upload everything; the app auto-deduplicates."
        )

        learn_files = st.file_uploader(
            "Upload log files to learn from",
            type=["txt", "log", "csv"],
            accept_multiple_files=True,
            key="learn_files",
            help="Upload any files. Only new/unknown patterns will be sent to AI.",
        )

        if not learn_files:
            st.info("👆 Upload files to discover and learn patterns.")

        elif not api_key:
            st.warning("API key not found. Add `ANTHROPIC_API_KEY` to Streamlit secrets.")

        else:
            # Ingest
            learn_raw: list[str] = []
            for uf in learn_files:
                learn_raw.extend(stream_lines(uf))
            learn_entries = reassemble_multiline(learn_raw)
            learn_clusters = cluster_logs(learn_entries)

            lib = st.session_state.get("pattern_library", _empty_library())
            existing_fps = set(lib.get("patterns", {}).keys())
            new_fps = set(learn_clusters.keys()) - existing_fps
            skipped_fps = set(learn_clusters.keys()) & existing_fps

            col_s1, col_s2, col_s3, col_s4 = st.columns(4)
            col_s1.metric("Log Entries", f"{len(learn_entries):,}")
            col_s2.metric("Unique Patterns", len(learn_clusters))
            col_s3.metric("🆕 New", len(new_fps))
            col_s4.metric("⏭️ Skipped (known)", len(skipped_fps))

            if not new_fps:
                st.success("All patterns already in library. No API calls needed!")
            else:
                est_calls = max(1, -(-len(new_fps) // batch_size))
                st.info(
                    f"Will make ~**{est_calls}** API call(s) to learn "
                    f"**{len(new_fps)}** new pattern(s). "
                    f"**{len(skipped_fps)}** known pattern(s) will be skipped."
                )

                if st.button("🧠 Learn Patterns", type="primary", use_container_width=True):
                    progress = st.progress(0, text="Learning patterns…")
                    start = time.time()

                    def _update(done, total):
                        progress.progress(done / total, text=f"Learning {done}/{total}…")

                    updated_lib, msgs = learn_patterns(
                        api_key=api_key,
                        clusters=learn_clusters,
                        siem_format=siem_format,
                        model=model,
                        samples_per_cluster=samples_per_cluster,
                        anonymize=anonymize,
                        max_workers=max_workers,
                        batch_size=batch_size,
                        existing_library=lib,
                        progress_callback=_update,
                    )

                    elapsed = time.time() - start
                    progress.empty()

                    st.session_state["pattern_library"] = updated_lib

                    for msg in msgs:
                        if "error" in msg.lower():
                            st.error(msg)
                        else:
                            st.success(msg)
                    st.toast(f"Done in {elapsed:.1f}s", icon="🧠")
                    st.rerun()

            # Show current library
            lib = st.session_state.get("pattern_library")
            if lib and lib.get("patterns"):
                st.divider()
                st.subheader("📚 Current Pattern Library")
                for fp, entry in lib["patterns"].items():
                    with st.expander(
                        f"Pattern `{fp[:12]}` — confidence {entry.get('confidence', 0):.0%}"
                    ):
                        st.markdown("**Sample:**")
                        st.code(entry.get("sample", "")[:300], language="log")
                        st.markdown("**Fields:**")
                        st.write(entry.get("field_names", []))
                        if entry.get("regex"):
                            st.markdown("**Regex:**")
                            st.code(entry["regex"], language="regex")

    # ==================================================================
    # APPLY TAB
    # ==================================================================
    with tab_apply:
        lib = st.session_state.get("pattern_library")

        if not lib or not lib.get("patterns"):
            st.warning(
                "No Pattern Library loaded. Use the **Learn** tab first, or "
                "import an existing library from the sidebar."
            )
            st.stop()

        n_patterns = len(lib["patterns"])
        st.markdown(
            f"Upload files for parsing. **{n_patterns} pattern(s)** in library — "
            f"matching logs will be parsed **locally with zero API calls**."
        )

        apply_files = st.file_uploader(
            "Upload log files for parsing",
            type=["txt", "log", "csv"],
            accept_multiple_files=True,
            key="apply_files",
            help="Upload as many files as you need. Parsing is local.",
        )

        if not apply_files:
            st.info("👆 Upload files to parse using your Pattern Library.")
            st.stop()

        # Ingest
        apply_raw: list[str] = []
        for uf in apply_files:
            apply_raw.extend(stream_lines(uf))
        apply_entries = reassemble_multiline(apply_raw)
        apply_clusters = cluster_logs(apply_entries)

        # Match stats
        lib_fps = set(lib["patterns"].keys())
        matched_fps = set(apply_clusters.keys()) & lib_fps
        unmatched_fps = set(apply_clusters.keys()) - lib_fps
        matched_lines = sum(len(apply_clusters[fp]) for fp in matched_fps)
        unmatched_lines = sum(len(apply_clusters[fp]) for fp in unmatched_fps)

        # Clear stale results on file change
        file_sig = hashlib.md5(str(len(apply_raw)).encode()).hexdigest()
        if st.session_state.get("_apply_sig") != file_sig:
            st.session_state.pop("apply_results", None)
            st.session_state["_apply_sig"] = file_sig

        col_a1, col_a2, col_a3, col_a4 = st.columns(4)
        col_a1.metric("Log Entries", f"{len(apply_entries):,}")
        col_a2.metric("Patterns Found", len(apply_clusters))
        col_a3.metric("✅ Library Match", f"{matched_lines:,} lines")
        col_a4.metric("❌ Unmatched", f"{unmatched_lines:,} lines")

        if unmatched_fps:
            st.warning(
                f"{len(unmatched_fps)} pattern(s) not in library "
                f"({unmatched_lines:,} lines). Go to the **Learn** tab to teach them."
            )

        if st.button("⚡ Parse with Library", type="primary", use_container_width=True):
            progress = st.progress(0, text="Parsing locally…")
            start = time.time()

            def _update(done, total):
                progress.progress(done / total, text=f"Parsing {done}/{total} clusters…")

            results, regex_manifest, warnings, unmatched = apply_library_to_entries(
                library=lib,
                clusters=apply_clusters,
                progress_callback=_update,
            )

            elapsed = time.time() - start
            progress.empty()

            for w in warnings:
                st.warning(w)

            if not results:
                st.error("No results. All patterns may be unmatched.")
                st.stop()

            st.toast(f"Parsed {len(results):,} entries in {elapsed:.1f}s — 0 API calls!", icon="⚡")

            st.session_state["apply_results"] = results
            st.session_state["apply_manifest"] = regex_manifest
            st.session_state["apply_elapsed"] = elapsed
            st.rerun()

        # -- Display Results -------------------------------------------
        if "apply_results" not in st.session_state:
            st.stop()

        results = st.session_state["apply_results"]
        regex_manifest = st.session_state.get("apply_manifest", [])
        elapsed = st.session_state.get("apply_elapsed", 0)

        st.divider()
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        col_m1.metric("Parsed Lines", f"{len(results):,}")
        col_m2.metric("Pattern Classes", len(regex_manifest))
        col_m3.metric("Processing Time", f"{elapsed:.1f}s")
        col_m4.metric("API Calls", "0")

        st.subheader("📊 Parsed Results")

        df = pd.DataFrame(results)
        col_order = ["_raw", "_cluster_id", "_confidence", "_source"] + [
            c for c in df.columns if not c.startswith("_")
        ]
        df = df[[c for c in col_order if c in df.columns]]

        tab_table, tab_raw = st.tabs(["Structured Table", "Raw vs. Parsed"])
        with tab_table:
            st.dataframe(df, use_container_width=True, height=400)
        with tab_raw:
            if results:
                sample_idx = st.slider("Select row", 0, len(results) - 1, 0, key="apply_slider")
                row = results[sample_idx]
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("**Raw Log**")
                    raw_display = row.get("_raw", "").replace("  |  ", "\n    ")
                    st.code(raw_display, language="log")
                with c2:
                    st.markdown("**Parsed JSON**")
                    display = {k: v for k, v in row.items() if not k.startswith("_")}
                    st.json(display)

        # Regex Manifest
        st.divider()
        st.subheader("🧩 Regex / SIEM Manifest")
        for entry in regex_manifest:
            with st.expander(
                f"Cluster `{entry['cluster_id']}` — {entry['sample_count']} lines  "
                f"(confidence {entry.get('confidence', 0):.0%})"
            ):
                st.code(entry.get("regex", ""), language="regex")
                if "grok_pattern" in entry:
                    st.markdown("**Grok Pattern**")
                    st.code(entry["grok_pattern"])
                if "kql_parse" in entry:
                    st.markdown("**KQL Parse**")
                    st.code(entry["kql_parse"], language="kql")
                if "fortisiem_parser" in entry:
                    st.markdown("**FortiSIEM Parser**")
                    st.code(entry["fortisiem_parser"], language="xml")

        # Exports
        st.divider()
        st.subheader("📦 Export")
        col_csv, col_regex, col_json = st.columns(3)

        with col_csv:
            csv_buf = io.StringIO()
            df.to_csv(csv_buf, index=False)
            st.download_button(
                "⬇️ Master CSV", data=csv_buf.getvalue(),
                file_name=f"log_harmonizer_{datetime.now():%Y%m%d_%H%M%S}.csv",
                mime="text/csv", use_container_width=True,
            )
        with col_regex:
            st.download_button(
                "⬇️ Regex Manifest",
                data=json.dumps(regex_manifest, indent=2),
                file_name=f"regex_manifest_{datetime.now():%Y%m%d_%H%M%S}.json",
                mime="application/json", use_container_width=True,
            )
        with col_json:
            st.download_button(
                "⬇️ Full Parsed JSON",
                data=json.dumps(results, indent=2, default=str),
                file_name=f"parsed_logs_{datetime.now():%Y%m%d_%H%M%S}.json",
                mime="application/json", use_container_width=True,
            )


if __name__ == "__main__":
    main()
