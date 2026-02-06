"""
AI-Powered Log Harmonizer & Regex Generator
=============================================
A Streamlit app that transforms unstructured text logs into structured
JSON/CSV data and generates reusable SIEM parsing rules (Regex/Grok/KQL).

Performance optimizations:
- Concurrent API calls (ThreadPoolExecutor)
- Batch multiple clusters into single prompts
- Optional fast model (Haiku) for bulk parsing
- Result caching to avoid redundant API calls
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

BATCH_SYSTEM_PROMPT = """<system_prompt>
You are a Security Data Engineer. You will receive MULTIPLE log pattern groups.
For EACH group, extract fields, normalize timestamps to ISO-8601, and generate a PCRE regex.

Output ONLY a valid JSON array — no markdown, no explanation. Each element must follow this schema:
{
  "group_id": "the group ID provided",
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

MODELS = {
    "Haiku 4.5 (fast, cheap)": "claude-haiku-4-5-20251001",
    "Sonnet 4 (balanced)": "claude-sonnet-4-20250514",
}

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
# Uses a capturing group instead of variable-width lookbehind for Python 3.13 compat
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
# 2. LOG FINGERPRINTING / CLUSTERING  (lightweight Drain-style)
# =========================================================================
def _tokenize(line: str) -> list[str]:
    """Split a log line into tokens, replacing variable-looking parts."""
    tokens = line.strip().split()
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
# 4. AI INTEGRATION  (Anthropic Claude — optimized)
# =========================================================================
def _get_client(api_key: str):
    """Return an Anthropic client."""
    import anthropic
    return anthropic.Anthropic(api_key=api_key)


def _parse_json_response(text: str) -> dict | list | None:
    """Extract JSON from an AI response, handling markdown fences etc."""
    text = text.strip()
    # Try markdown fences first
    json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if json_match:
        text = json_match.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Find outermost JSON structure
    for opener, closer in [("[", "]"), ("{", "}")]:
        try:
            start = text.index(opener)
            end = text.rindex(closer) + 1
            return json.loads(text[start:end])
        except (ValueError, json.JSONDecodeError):
            continue
    return None


def call_claude_single(
    client, model: str, sample_lines: list[str], siem_format: str
) -> tuple[dict | None, str | None]:
    """Send a single cluster's samples to Claude. Returns (result, error_msg)."""
    siem_extra = ""
    if siem_format == "grok":
        siem_extra = (
            "\nAdditionally, convert the PCRE regex into an Elastic Grok pattern "
            'and include it as "grok_pattern" in your JSON output.'
        )
    elif siem_format == "kql":
        siem_extra = (
            "\nAdditionally, generate a Microsoft Sentinel KQL parse statement "
            'and include it as "kql_parse" in your JSON output.'
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
            model=model,
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        raw_text = response.content[0].text
        parsed = _parse_json_response(raw_text)
        if parsed is None:
            return None, f"JSON parse failed. Raw response: {raw_text[:300]}"
        return parsed, None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def call_claude_batch(
    client,
    model: str,
    batch: list[tuple[str, list[str]]],
    siem_format: str,
) -> tuple[dict[str, dict | None], str | None]:
    """Send multiple clusters in ONE API call. Returns ({group_id: result}, error_msg)."""
    siem_extra = ""
    if siem_format == "grok":
        siem_extra = '\nFor each group, also include a "grok_pattern" field.'
    elif siem_format == "kql":
        siem_extra = '\nFor each group, also include a "kql_parse" field.'

    groups_text = ""
    for group_id, samples in batch:
        groups_text += f"\n--- GROUP {group_id} ---\n" + "\n".join(samples) + "\n"

    user_message = (
        f"Analyze each group of log samples below. Return a JSON array with one "
        f"object per group.{siem_extra}\n{groups_text}"
    )

    try:
        response = client.messages.create(
            model=model,
            max_tokens=4096,
            system=BATCH_SYSTEM_PROMPT,
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
# 5. CONCURRENT + BATCHED PROCESSING ENGINE
# =========================================================================
def process_clusters(
    api_key: str,
    clusters: dict[str, list[str]],
    siem_format: str,
    model: str,
    samples_per_cluster: int,
    anonymize: bool,
    max_workers: int,
    batch_size: int,
    progress_callback=None,
) -> tuple[list[dict], list[dict], list[str]]:
    """
    Process all clusters with concurrency and optional batching.
    Returns (results_rows, regex_manifest, errors).
    """
    client = _get_client(api_key)
    cluster_items = list(clusters.items())
    total = len(cluster_items)

    # --- Prepare samples (anonymize if needed) ---
    prepared: list[tuple[str, list[str], dict]] = []  # (fp, samples, anon_mapping)
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

    # --- Decide strategy: batch or concurrent singles ---
    ai_results: dict[str, dict | None] = {}
    errors: list[str] = []
    completed = 0

    if batch_size > 1 and total > 1:
        # ---- BATCHED MODE: group clusters into batches, run batches concurrently ----
        batches: list[list[tuple[str, list[str], dict]]] = []
        for i in range(0, len(prepared), batch_size):
            batches.append(prepared[i : i + batch_size])

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
                        key = fp[:12]
                        result = batch_result.get(key)
                        if result and anonymize and anon_mapping:
                            result = deanonymize_result(result, anon_mapping)
                        ai_results[fp] = result
                        completed += 1
                except Exception as e:
                    errors.append(f"Batch thread error: {type(e).__name__}: {e}")
                if progress_callback:
                    progress_callback(min(completed, total), total)
    else:
        # ---- CONCURRENT SINGLES MODE ----
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

    # --- Aggregate results ---
    results: list[dict] = []
    regex_manifest: list[dict] = []

    for fp, lines in cluster_items:
        ai_result = ai_results.get(fp)
        if ai_result is None:
            continue

        raw_regex = ai_result.get("generated_regex", "")
        manifest_entry: dict = {
            "cluster_id": fp[:12],
            "sample_count": len(lines),
            "regex": raw_regex,
            "confidence": ai_result.get("confidence_score", 0),
        }
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

        parsed = ai_result.get("parsed_data", {})
        for line in lines:
            row = flatten_parsed(parsed)
            row["_raw"] = line
            row["_cluster_id"] = fp[:12]
            row["_confidence"] = ai_result.get("confidence_score", 0)
            results.append(row)

    return results, regex_manifest, errors


# =========================================================================
# 6. SIEM FORMAT CONVERTERS
# =========================================================================
def regex_to_grok(regex: str) -> str:
    """Best-effort conversion of a named-group PCRE regex to Grok syntax."""
    def _replace(m: re.Match) -> str:
        name = m.group(1)
        pattern = m.group(2)
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
    return f"| parse RawLog with {placeholders}  // Adjust delimiters to match your data"


# =========================================================================
# 7. RESULT AGGREGATION
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
# 8. STREAMLIT UI
# =========================================================================
def main():
    # -- Sidebar -------------------------------------------------------
    with st.sidebar:
        st.image(
            "https://img.icons8.com/fluency/96/parse-from-clipboard.png", width=60
        )
        st.title("⚙️ Settings")

        try:
            api_key = st.secrets["ANTHROPIC_API_KEY"]
        except (KeyError, FileNotFoundError):
            api_key = ""

        model_choice = st.selectbox(
            "AI Model",
            options=list(MODELS.keys()),
            index=0,
            help="Haiku = ~3x faster & cheaper. Sonnet = higher accuracy.",
        )
        model = MODELS[model_choice]

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

        st.divider()
        st.markdown("**⚡ Performance**")

        samples_per_cluster = st.slider(
            "Samples per cluster",
            min_value=1,
            max_value=5,
            value=2,
            help="Lines per cluster sent to the AI.",
        )

        max_workers = st.slider(
            "Parallel workers",
            min_value=1,
            max_value=8,
            value=4,
            help="Concurrent API calls. Higher = faster but may hit rate limits.",
        )

        batch_size = st.slider(
            "Clusters per API call",
            min_value=1,
            max_value=10,
            value=5,
            help="Batch multiple clusters into one prompt. Reduces total API calls.",
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
        st.warning(
            "API key not found. Add `ANTHROPIC_API_KEY` to your Streamlit secrets "
            "(Settings → Secrets)."
        )
        st.stop()

    # -- Ingest & Cluster -----------------------------------------------
    all_lines: list[str] = []
    file_sources: dict[str, list[str]] = {}

    for uf in uploaded_files:
        lines = list(stream_lines(uf))
        all_lines.extend(lines)
        file_sources[uf.name] = lines

    # Detect file changes and clear stale results
    file_sig = hashlib.md5(
        "|".join(sorted(file_sources.keys())).encode()
        + str(len(all_lines)).encode()
    ).hexdigest()
    if st.session_state.get("_file_sig") != file_sig:
        st.session_state.pop("results", None)
        st.session_state.pop("regex_manifest", None)
        st.session_state.pop("siem_format", None)
        st.session_state.pop("elapsed", None)
        st.session_state["_file_sig"] = file_sig

    st.success(
        f"Loaded **{len(all_lines):,}** lines from **{len(uploaded_files)}** file(s)."
    )

    with st.expander("📄 Raw log preview (first 20 lines)", expanded=False):
        st.code("\n".join(all_lines[:20]), language="log")

    clusters = cluster_logs(all_lines)
    n_clusters = len(clusters)
    n_api_calls = max(1, -(-n_clusters // batch_size))  # ceil division
    st.info(
        f"Identified **{n_clusters}** unique log pattern(s) — "
        f"will make ~**{n_api_calls}** API call(s) "
        f"with **{max_workers}** parallel workers."
    )

    # -- Process Button -------------------------------------------------
    if st.button("🚀 Harmonize Logs", type="primary", use_container_width=True):
        progress = st.progress(0, text="Processing clusters…")
        start_time = time.time()

        def _update(done, total):
            progress.progress(
                done / total, text=f"Processing {done}/{total} clusters…"
            )

        results, regex_manifest, proc_errors = process_clusters(
            api_key=api_key,
            clusters=clusters,
            siem_format=siem_format,
            model=model,
            samples_per_cluster=samples_per_cluster,
            anonymize=anonymize,
            max_workers=max_workers,
            batch_size=batch_size,
            progress_callback=_update,
        )

        elapsed = time.time() - start_time
        progress.empty()

        # Show any errors that occurred during processing
        for err in proc_errors:
            st.error(err)

        if not results:
            st.error("No results were produced. Check your API key and log format.")
            st.stop()

        st.toast(f"Done in {elapsed:.1f}s", icon="⚡")

        # Store in session
        st.session_state["results"] = results
        st.session_state["regex_manifest"] = regex_manifest
        st.session_state["siem_format"] = siem_format
        st.session_state["elapsed"] = elapsed
        st.rerun()

    # -- Display Results ------------------------------------------------
    if "results" not in st.session_state:
        st.stop()

    results = st.session_state["results"]
    regex_manifest = st.session_state["regex_manifest"]
    siem_format = st.session_state.get("siem_format", "regex")
    elapsed = st.session_state.get("elapsed", 0)

    st.divider()
    col_m1, col_m2, col_m3 = st.columns(3)
    col_m1.metric("Parsed Lines", f"{len(results):,}")
    col_m2.metric("Pattern Classes", len(regex_manifest))
    col_m3.metric("Processing Time", f"{elapsed:.1f}s")

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
