"""
AI-Powered Log Harmonizer & Regex Generator
=============================================
A Streamlit app that transforms unstructured text logs into structured
JSON/CSV data and generates reusable SIEM parsing rules (Regex/Grok/KQL).
"""

import streamlit as st
import pandas as pd
import json
import re
import io
import hashlib
import time
from collections import defaultdict
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
You are a Security Data Engineer. Given a raw log line:
1. Extract all meaningful variables into a valid JSON object.
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
    "additional_fields": {}
  },
  "generated_regex": "^(?P<timestamp>...) ...",
  "confidence_score": 0.95
}
</system_prompt>"""

SIEM_FORMATS = {
    "Splunk (Regex)": "regex",
    "Elastic (Grok)": "grok",
    "Sentinel (KQL)": "kql",
}

# Patterns used by the anonymization mode
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
# Common username patterns like "user=admin" or "User: jdoe"
USERNAME_PATTERN = re.compile(
    r"(?<=[Uu]ser(?:name)?[=: ]+)[\w.\-\\]+", re.IGNORECASE
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
        mapping[token] = m.group(0)
        counter["user"] += 1
        return token

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
# 2. LOG FINGERPRINTING / CLUSTERING  (lightweight Drain-style)
# =========================================================================
def _tokenize(line: str) -> list[str]:
    """Split a log line into tokens, replacing variable-looking parts."""
    tokens = line.strip().split()
    normalized: list[str] = []
    for t in tokens:
        # Replace things that look like variables with a wildcard
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
    """Return a structural hash for a log line (Drain-style fingerprint)."""
    tokens = _tokenize(line)
    skeleton = " ".join(tokens)
    return hashlib.md5(skeleton.encode()).hexdigest()


def cluster_logs(lines: list[str]) -> dict[str, list[str]]:
    """Group log lines by structural fingerprint."""
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
    """Yield non-empty lines from an uploaded file in chunks."""
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


# =========================================================================
# 4. AI INTEGRATION  (Anthropic Claude via REST)
# =========================================================================
def call_claude(api_key: str, sample_lines: list[str], siem_format: str) -> dict | None:
    """Send sample log lines to Claude and return structured JSON."""
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)

    siem_extra = ""
    if siem_format == "grok":
        siem_extra = (
            "\nAdditionally, convert the PCRE regex into an Elastic Grok pattern "
            "and include it as \"grok_pattern\" in your JSON output."
        )
    elif siem_format == "kql":
        siem_extra = (
            "\nAdditionally, generate a Microsoft Sentinel KQL parse statement "
            "and include it as \"kql_parse\" in your JSON output."
        )

    user_message = (
        "Analyze the following raw log sample(s). For each unique format you see, "
        "return ONE JSON object per the schema in your instructions.\n"
        "If multiple samples share the same format, return only one object.\n"
        f"{siem_extra}\n\n"
        "--- RAW LOG SAMPLES ---\n"
        + "\n".join(sample_lines)
    )

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        text = response.content[0].text.strip()

        # Try to extract JSON from the response (handle markdown fences)
        json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if json_match:
            text = json_match.group(1).strip()

        return json.loads(text)
    except json.JSONDecodeError:
        # Attempt lenient extraction
        try:
            start = text.index("{")
            end = text.rindex("}") + 1
            return json.loads(text[start:end])
        except Exception:
            return None
    except Exception as e:
        st.error(f"API error: {e}")
        return None


# =========================================================================
# 5. SIEM FORMAT CONVERTERS
# =========================================================================
def regex_to_grok(regex: str) -> str:
    """Best-effort conversion of a named-group PCRE regex to Grok syntax."""
    def _replace(m: re.Match) -> str:
        name = m.group(1)
        pattern = m.group(2)
        # Map common sub-patterns to Grok types
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
    """Generate a minimal KQL parse statement from regex field names."""
    placeholders = " ".join(f"*{f}:string*" for f in fields)
    return f'| parse RawLog with {placeholders}  // Adjust delimiters to match your data'


# =========================================================================
# 6. RESULT AGGREGATION
# =========================================================================
def flatten_parsed(parsed_data: dict) -> dict:
    """Flatten nested parsed_data into a single-level dict for DataFrame."""
    flat: dict = {}
    for k, v in parsed_data.items():
        if isinstance(v, dict):
            for sub_k, sub_v in v.items():
                flat[f"{k}.{sub_k}"] = sub_v
        else:
            flat[k] = v
    return flat


# =========================================================================
# 7. STREAMLIT UI
# =========================================================================
def main():
    # -- Sidebar -------------------------------------------------------
    with st.sidebar:
        st.image("https://img.icons8.com/fluency/96/parse-from-clipboard.png", width=60)
        st.title("⚙️ Settings")

        api_key = st.text_input(
            "Anthropic API Key",
            type="password",
            help="Your Claude API key. Required for AI parsing.",
        )

        siem_choice = st.selectbox(
            "SIEM Output Format",
            options=list(SIEM_FORMATS.keys()),
            index=0,
        )
        siem_format = SIEM_FORMATS[siem_choice]

        anonymize = st.toggle(
            "🔒 Anonymization Mode",
            value=False,
            help="Mask IPs, emails, and usernames before sending to AI.",
        )

        samples_per_cluster = st.slider(
            "Samples per pattern cluster",
            min_value=1,
            max_value=5,
            value=2,
            help="How many example lines per cluster to send to the AI.",
        )

        st.divider()
        st.caption("Built for SOC analysts & security engineers.")

    # -- Header --------------------------------------------------------
    st.title("🔍 Log Harmonizer & Regex Generator")
    st.markdown(
        "Upload raw `.txt` log files → get structured data + SIEM-ready parsing rules."
    )

    # -- File Upload ---------------------------------------------------
    uploaded_files = st.file_uploader(
        "Upload log files",
        type=["txt", "log", "csv"],
        accept_multiple_files=True,
        help="Upload one or more raw log files.",
    )

    if not uploaded_files:
        st.info("👆 Upload one or more log files to get started.")
        st.stop()

    if not api_key:
        st.warning("Please enter your Anthropic API key in the sidebar to enable AI parsing.")
        st.stop()

    # -- Ingest & Cluster -----------------------------------------------
    all_lines: list[str] = []
    file_sources: dict[str, list[str]] = {}

    for uf in uploaded_files:
        lines = list(stream_lines(uf))
        all_lines.extend(lines)
        file_sources[uf.name] = lines

    st.success(f"Loaded **{len(all_lines):,}** lines from **{len(uploaded_files)}** file(s).")

    with st.expander("📄 Raw log preview (first 20 lines)", expanded=False):
        st.code("\n".join(all_lines[:20]), language="log")

    clusters = cluster_logs(all_lines)
    st.info(f"Identified **{len(clusters)}** unique log pattern(s) via fingerprinting.")

    # -- Process Button -------------------------------------------------
    if st.button("🚀 Harmonize Logs", type="primary", use_container_width=True):
        results: list[dict] = []
        regex_manifest: list[dict] = []
        progress = st.progress(0, text="Processing clusters…")

        cluster_items = list(clusters.items())
        total = len(cluster_items)

        for idx, (fp, lines) in enumerate(cluster_items):
            progress.progress(
                (idx + 1) / total,
                text=f"Processing cluster {idx + 1}/{total} ({len(lines)} lines)…",
            )

            # Pick representative samples
            samples = lines[: samples_per_cluster]

            # Anonymize if enabled
            anon_mapping: dict = {}
            if anonymize:
                anon_samples = []
                combined_mapping: dict = {}
                for s in samples:
                    masked, mapping = anonymize_line(s)
                    anon_samples.append(masked)
                    combined_mapping.update(mapping)
                samples = anon_samples
                anon_mapping = combined_mapping

            # Call AI
            ai_result = call_claude(api_key, samples, siem_format)
            if ai_result is None:
                st.warning(f"⚠️ Cluster {fp[:8]}… returned no valid JSON. Skipping.")
                continue

            # De-anonymize
            if anonymize and anon_mapping:
                ai_result = deanonymize_result(ai_result, anon_mapping)

            # Build regex manifest entry
            manifest_entry: dict = {
                "cluster_id": fp[:12],
                "sample_count": len(lines),
                "regex": ai_result.get("generated_regex", ""),
                "confidence": ai_result.get("confidence_score", 0),
            }

            # Add SIEM-specific fields
            raw_regex = ai_result.get("generated_regex", "")
            if siem_format == "grok":
                manifest_entry["grok_pattern"] = ai_result.get(
                    "grok_pattern", regex_to_grok(raw_regex)
                )
            elif siem_format == "kql":
                fields = list((ai_result.get("parsed_data") or {}).keys())
                manifest_entry["kql_parse"] = ai_result.get(
                    "kql_parse", regex_to_kql(raw_regex, fields)
                )

            regex_manifest.append(manifest_entry)

            # Expand result to all lines in the cluster
            parsed = ai_result.get("parsed_data", {})
            for line in lines:
                row = flatten_parsed(parsed)
                row["_raw"] = line
                row["_cluster_id"] = fp[:12]
                row["_confidence"] = ai_result.get("confidence_score", 0)
                results.append(row)

            # Be kind to rate limits
            if idx < total - 1:
                time.sleep(0.3)

        progress.empty()

        if not results:
            st.error("No results were produced. Check your API key and log format.")
            st.stop()

        # Store in session
        st.session_state["results"] = results
        st.session_state["regex_manifest"] = regex_manifest
        st.session_state["siem_format"] = siem_format
        st.rerun()

    # -- Display Results ------------------------------------------------
    if "results" not in st.session_state:
        st.stop()

    results = st.session_state["results"]
    regex_manifest = st.session_state["regex_manifest"]
    siem_format = st.session_state.get("siem_format", "regex")

    st.divider()
    st.subheader("📊 Parsed Results")

    df = pd.DataFrame(results)
    col_order = ["_raw", "_cluster_id", "_confidence"] + [
        c for c in df.columns if not c.startswith("_")
    ]
    df = df[[c for c in col_order if c in df.columns]]

    # Side-by-side view
    tab_table, tab_raw = st.tabs(["Structured Table", "Raw vs. Parsed"])
    with tab_table:
        st.dataframe(df, use_container_width=True, height=400)

    with tab_raw:
        if len(results) > 0:
            sample_idx = st.slider("Select row", 0, len(results) - 1, 0)
            row = results[sample_idx]
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Raw Log**")
                st.code(row.get("_raw", ""), language="log")
            with c2:
                st.markdown("**Parsed JSON**")
                display = {k: v for k, v in row.items() if not k.startswith("_")}
                st.json(display)

    # -- Regex Manifest -------------------------------------------------
    st.divider()
    st.subheader("🧩 Regex / SIEM Manifest")

    for entry in regex_manifest:
        with st.expander(
            f"Cluster `{entry['cluster_id']}` — {entry['sample_count']} lines  "
            f"(confidence {entry['confidence']:.0%})"
        ):
            st.code(entry["regex"], language="regex")
            if "grok_pattern" in entry:
                st.markdown("**Grok Pattern**")
                st.code(entry["grok_pattern"])
            if "kql_parse" in entry:
                st.markdown("**KQL Parse**")
                st.code(entry["kql_parse"], language="kql")

    # -- Exports --------------------------------------------------------
    st.divider()
    st.subheader("📦 Export")

    col_csv, col_regex, col_json = st.columns(3)

    with col_csv:
        csv_buf = io.StringIO()
        df.to_csv(csv_buf, index=False)
        st.download_button(
            "⬇️  Master CSV",
            data=csv_buf.getvalue(),
            file_name=f"log_harmonizer_{datetime.now():%Y%m%d_%H%M%S}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with col_regex:
        manifest_text = json.dumps(regex_manifest, indent=2)
        st.download_button(
            "⬇️  Regex Manifest (JSON)",
            data=manifest_text,
            file_name=f"regex_manifest_{datetime.now():%Y%m%d_%H%M%S}.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_json:
        all_json = json.dumps(results, indent=2, default=str)
        st.download_button(
            "⬇️  Full Parsed JSON",
            data=all_json,
            file_name=f"parsed_logs_{datetime.now():%Y%m%d_%H%M%S}.json",
            mime="application/json",
            use_container_width=True,
        )


if __name__ == "__main__":
    main()
