"""Data management and file inspection for iqAudi360 scan runs."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from strix.core.paths import run_dir_for, run_record_path, runs_base_dir

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}

SARIF_LEVEL_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


def _safe_load_json(file_path: Path, default: Any = None) -> Any:
    """Safely read and parse a JSON file, returning default on error."""
    if not file_path.is_file():
        return default
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return json.loads(content)
    except Exception as exc:
        logger.debug("Failed to read JSON from %s: %s", file_path, exc)
        return default


def format_duration(start_iso: str | None, end_iso: str | None) -> str:
    """Format duration between start and end ISO timestamps."""
    if not start_iso:
        return "N/A"
    try:
        start = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
        if end_iso:
            end = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
        else:
            end = datetime.now(timezone.utc)
        diff = int((end - start).total_seconds())
        if diff < 0:
            return "0s"
        hours, remainder = divmod(diff, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        if minutes > 0:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"
    except Exception:
        return "N/A"


def extract_primary_target(record: dict[str, Any], default: str = "Unknown") -> str:
    """Extract human-readable target string from run.json record."""
    targets = record.get("targets_info") or record.get("targets")
    if isinstance(targets, list) and targets:
        first = targets[0]
        if isinstance(first, dict):
            return str(first.get("original") or first.get("target_url") or first.get("target") or default)
        if isinstance(first, str):
            return first
    return default


def parse_sarif_findings(sarif_data: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Parse findings from SARIF 2.1.0 JSON format."""
    if not isinstance(sarif_data, dict):
        return []

    findings: list[dict[str, Any]] = []
    runs = sarif_data.get("runs") or []
    for run in runs:
        if not isinstance(run, dict):
            continue

        # Extract rules for rule metadata
        driver = run.get("tool", {}).get("driver", {})
        rules_list = driver.get("rules") or []
        rules_map: dict[str, dict[str, Any]] = {}
        for r in rules_list:
            if isinstance(r, dict) and "id" in r:
                rules_map[r["id"]] = r

        results = run.get("results") or []
        for idx, res in enumerate(results):
            if not isinstance(res, dict):
                continue

            rule_id = res.get("ruleId") or f"RULE-{idx + 1}"
            rule_meta = rules_map.get(rule_id, {})

            # Determine severity
            strix_props = res.get("properties", {}).get("strix", {})
            raw_severity = strix_props.get("severity") or res.get("level") or rule_meta.get("properties", {}).get("security-severity")
            if not raw_severity or str(raw_severity).lower() in ("error", "warning", "note", "none"):
                level = res.get("level", "warning").lower()
                severity = SARIF_LEVEL_MAP.get(level, "medium")
            else:
                severity = str(raw_severity).lower().strip()

            # Location extraction
            locations = res.get("locations") or []
            loc_str = "Global / General"
            line_no = None
            if locations and isinstance(locations[0], dict):
                phys = locations[0].get("physicalLocation")
                if isinstance(phys, dict):
                    artifact = phys.get("artifactLocation", {}).get("uri")
                    region = phys.get("region", {})
                    line_no = region.get("startLine")
                    if artifact:
                        loc_str = artifact + (f":{line_no}" if line_no else "")
                elif "logicalLocations" in locations[0]:
                    log_loc = locations[0]["logicalLocations"]
                    if log_loc and isinstance(log_loc[0], dict):
                        loc_str = log_loc[0].get("fullyQualifiedName") or log_loc[0].get("name") or loc_str

            # Message / description
            msg_obj = res.get("message")
            msg_text = msg_obj.get("text", "") if isinstance(msg_obj, dict) else str(msg_obj or "")

            title = strix_props.get("title") or rule_meta.get("shortDescription", {}).get("text") or msg_text.splitlines()[0] if msg_text else f"Finding {rule_id}"
            if len(title) > 120:
                title = title[:117] + "..."

            description = strix_props.get("description") or rule_meta.get("fullDescription", {}).get("text") or msg_text
            recommendation = strix_props.get("recommendation") or rule_meta.get("help", {}).get("text") or ""
            evidence = strix_props.get("poc") or strix_props.get("evidence") or ""

            finding_id = strix_props.get("id") or res.get("id") or f"vuln-{idx + 1:04d}"

            findings.append({
                "id": str(finding_id),
                "title": title,
                "severity": severity,
                "cwe": rule_id if rule_id.startswith("CWE-") else strix_props.get("cwe", rule_id),
                "target": loc_str,
                "description": description,
                "evidence": evidence,
                "recommendation": recommendation,
                "cvss": strix_props.get("cvss"),
                "source": "sarif",
                "raw": res,
            })

    return findings


def parse_vulnerabilities_json(vulns_data: Any) -> list[dict[str, Any]]:
    """Parse findings from vulnerabilities.json."""
    if not isinstance(vulns_data, list):
        return []

    findings: list[dict[str, Any]] = []
    for idx, v in enumerate(vulns_data):
        if not isinstance(v, dict):
            continue

        fid = v.get("id") or f"vuln-{idx + 1:04d}"
        title = v.get("title") or f"Vulnerability {fid}"
        raw_sev = str(v.get("severity") or "medium").lower().strip()
        sev = raw_sev if raw_sev in SEVERITY_ORDER else "medium"

        target = v.get("target") or v.get("endpoint") or v.get("url") or ""
        if not target and "code_locations" in v and isinstance(v["code_locations"], list) and v["code_locations"]:
            cloc = v["code_locations"][0]
            target = f"{cloc.get('file', '')}:{cloc.get('start_line', '')}".rstrip(":")

        findings.append({
            "id": str(fid),
            "title": title,
            "severity": sev,
            "cwe": v.get("cwe") or v.get("cve") or "N/A",
            "target": target or "Target System",
            "description": v.get("description") or "",
            "evidence": v.get("poc") or v.get("evidence") or "",
            "recommendation": v.get("fix_recommendation") or v.get("recommendation") or "",
            "cvss": v.get("cvss"),
            "source": "vulnerabilities_json",
            "raw": v,
        })

    return findings


def get_scan_findings(run_dir: Path) -> list[dict[str, Any]]:
    """Load findings from a scan directory, preferring SARIF and falling back to vulnerabilities.json."""
    sarif_data = _safe_load_json(run_dir / "findings.sarif")
    sarif_findings = parse_sarif_findings(sarif_data)

    vulns_data = _safe_load_json(run_dir / "vulnerabilities.json")
    json_findings = parse_vulnerabilities_json(vulns_data)

    if sarif_findings and json_findings:
        # Merge extra fields (e.g. detailed poc, remediation) if SARIF lacks them
        json_map = {f["id"]: f for f in json_findings}
        for sf in sarif_findings:
            jf = json_map.get(sf["id"])
            if jf:
                if not sf.get("evidence") and jf.get("evidence"):
                    sf["evidence"] = jf["evidence"]
                if not sf.get("recommendation") and jf.get("recommendation"):
                    sf["recommendation"] = jf["recommendation"]
                if not sf.get("description") and jf.get("description"):
                    sf["description"] = jf["description"]
        findings = sarif_findings
    elif sarif_findings:
        findings = sarif_findings
    else:
        findings = json_findings

    # Sort by severity
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return findings


def calculate_severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Calculate severity distribution from list of findings."""
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": len(findings),
    }
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["low"] += 1
    return counts


def parse_agents_from_run(run_dir: Path) -> list[dict[str, Any]]:
    """Derive list of real agents and their status from .state/agents.json or coverage.json."""
    agents: list[dict[str, Any]] = []

    # Try .state/agents.json first
    state_agents_file = run_dir / ".state" / "agents.json"
    state_data = _safe_load_json(state_agents_file)
    if isinstance(state_data, dict) and "names" in state_data:
        names = state_data.get("names") or {}
        statuses = state_data.get("statuses") or {}
        metadata = state_data.get("metadata") or {}
        parent_of = state_data.get("parent_of") or {}

        for aid, name in names.items():
            meta = metadata.get(aid) or {}
            skills = meta.get("skills") or []
            task = meta.get("task") or ""
            status = statuses.get(aid, "completed")
            is_root = parent_of.get(aid) is None

            agents.append({
                "id": str(aid),
                "name": str(name),
                "status": str(status),
                "skills": skills,
                "task": task[:300] + ("..." if len(task) > 300 else ""),
                "is_root": is_root,
            })

    # If no agents found yet, check coverage.json
    if not agents:
        cov_file = run_dir / "coverage.json"
        cov_data = _safe_load_json(cov_file)
        if isinstance(cov_data, dict):
            machine_obs = cov_data.get("machine_observed") or {}
            obs_agents = machine_obs.get("agents") or []
            for a in obs_agents:
                if isinstance(a, dict):
                    agents.append({
                        "id": str(a.get("agent_id") or a.get("id") or ""),
                        "name": str(a.get("agent_name") or a.get("name") or "Agent"),
                        "status": str(a.get("status") or "completed"),
                        "skills": a.get("skills") or [],
                        "task": str(a.get("task") or "")[:300],
                        "is_root": bool(a.get("is_root")),
                    })

    # If still none, check strix.log for registered agents
    if not agents:
        log_file = run_dir / "strix.log"
        if log_file.is_file():
            try:
                content = log_file.read_text(encoding="utf-8", errors="replace")
                # Look for 'agent.register <id> (<name>)'
                matches = re.findall(r"agent\.register\s+([0-9a-fA-F]+)\s+\(([^)]+)\)", content)
                seen = set()
                for aid, name in matches:
                    if aid not in seen:
                        seen.add(aid)
                        agents.append({
                            "id": aid,
                            "name": name,
                            "status": "completed",
                            "skills": [],
                            "task": "",
                            "is_root": "Root" in name,
                        })
            except Exception:
                pass

    return agents


def format_log_for_ui(line: str) -> str:
    """Format raw backend log line into clean user-facing iqAudi360 presentation text."""
    if not line:
        return line
    line = re.sub(r"strix\.report\.coverage", "iqAudi360 Coverage", line)
    line = re.sub(r"strix\.llm\.request_log", "iqAudi360 LLM Activity", line)
    line = re.sub(r"strix\.core\.runner", "iqAudi360 Engine", line)
    line = re.sub(r"strix\.core\.agents", "iqAudi360 Agent Coordinator", line)
    line = re.sub(r"strix\.agents\.factory", "iqAudi360 Agent Factory", line)
    line = re.sub(r"strix\.agents\.prompt", "iqAudi360 Prompts", line)
    line = re.sub(r"strix\.report\.sarif", "iqAudi360 SARIF Emitter", line)
    line = re.sub(r"strix\.report\.state", "iqAudi360 Report State", line)
    line = re.sub(r"strix\.report\.writer", "iqAudi360 Report Writer", line)
    line = re.sub(r"strix\.runtime\.docker_client", "iqAudi360 Sandbox Client", line)
    line = re.sub(r"strix\.runtime\.session_manager", "iqAudi360 Session Manager", line)
    line = re.sub(r"strix\.runtime\.backends", "iqAudi360 Runtime", line)
    line = re.sub(r"strix\.runtime\.caido_bootstrap", "iqAudi360 Proxy Client", line)
    line = re.sub(r"strix\.skills", "iqAudi360 Skills", line)
    line = re.sub(r"strix\.telemetry", "iqAudi360 Telemetry", line)
    line = re.sub(r"strix-sandbox", "iqAudi360-sandbox", line)
    line = re.sub(r"ghcr\.io/usestrix/", "ghcr.io/iqaudi360/", line)
    line = re.sub(r"strix_runs", "iqaudi360_runs", line)
    line = re.sub(r"strix\.log", "iqAudi360.log", line)
    line = re.sub(r"(?<![a-zA-Z0-9_])Strix(?![a-zA-Z0-9_])", "iqAudi360", line)
    line = re.sub(r"(?<![a-zA-Z0-9_])strix(?![a-zA-Z0-9_])", "iqaudi360", line)
    return line


def get_scan_detail(run_name: str) -> dict[str, Any] | None:
    """Load full details for a single scan run."""
    run_dir = run_dir_for(run_name)
    if not run_dir.is_dir():
        # Check direct path under runs_base_dir
        candidate = runs_base_dir() / run_name
        if candidate.is_dir():
            run_dir = candidate
        else:
            return None

    record = _safe_load_json(run_record_path(run_dir), default={})
    findings = get_scan_findings(run_dir)
    severity_counts = calculate_severity_counts(findings)
    agents = parse_agents_from_run(run_dir)
    coverage_data = _safe_load_json(run_dir / "coverage.json")

    # Log tail
    log_file = run_dir / "strix.log"
    log_lines: list[str] = []
    if log_file.is_file():
        try:
            # Read last 300 lines with presentation formatting for UI
            with log_file.open("r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
                log_lines = [format_log_for_ui(line.rstrip()) for line in all_lines[-300:]]
        except Exception as exc:
            logger.debug("Failed reading log file: %s", exc)

    # Markdown report
    report_md_file = run_dir / "penetration_test_report.md"
    report_md = ""
    if report_md_file.is_file():
        try:
            report_md = report_md_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass

    status = record.get("status") or "unknown"
    start_time = record.get("start_time")
    end_time = record.get("end_time")

    # Has files availability flags
    has_sarif = (run_dir / "findings.sarif").is_file()
    has_json = (run_dir / "vulnerabilities.json").is_file() or (run_dir / "run.json").is_file()
    has_coverage = (run_dir / "coverage.json").is_file()
    has_report = (run_dir / "penetration_test_report.md").is_file()
    has_pdf = True  # We can generate on demand

    return {
        "run_id": run_name,
        "run_name": run_name,
        "run_dir": str(run_dir),
        "target": extract_primary_target(record, default=run_name),
        "targets_info": record.get("targets_info") or [],
        "scan_mode": record.get("scan_mode") or "deep",
        "scope_mode": record.get("scope_mode") or "auto",
        "status": status,
        "start_time": start_time,
        "end_time": end_time,
        "duration": format_duration(start_time, end_time),
        "finished": bool(record.get("finished") or end_time or status in ("completed", "stopped", "failed", "interrupted")),
        "findings": findings,
        "severity_counts": severity_counts,
        "agents": agents,
        "coverage": coverage_data,
        "log_lines": log_lines,
        "report_md": report_md,
        "has_sarif": has_sarif,
        "has_json": has_json,
        "has_coverage": has_coverage,
        "has_report": has_report,
        "has_pdf": has_pdf,
        "llm_usage": record.get("llm_usage") or {},
        "raw_record": record,
    }


def list_all_scans(tenant_id: str | None = None) -> list[dict[str, Any]]:
    """List all scans from iqaudi360_runs directory, optionally filtered by tenant."""
    base_dir = runs_base_dir()
    if not base_dir.is_dir():
        return []

    allowed_scan_ids: set[str] | None = None
    if tenant_id:
        try:
            from strix.gui.auth.db import list_scans_for_tenant
            allowed_scan_ids = set(list_scans_for_tenant(tenant_id))
        except Exception:
            allowed_scan_ids = None

    scans: list[dict[str, Any]] = []
    for child in base_dir.iterdir():
        if not child.is_dir():
            continue
        if allowed_scan_ids is not None and child.name not in allowed_scan_ids:
            continue

        record = _safe_load_json(run_record_path(child), default={})
        findings = get_scan_findings(child)
        sev_counts = calculate_severity_counts(findings)

        status = record.get("status") or "unknown"
        start_time = record.get("start_time")
        end_time = record.get("end_time")

        # Fallback mtime for sorting if start_time is missing
        try:
            mtime = child.stat().st_mtime
        except Exception:
            mtime = 0

        scans.append({
            "run_id": child.name,
            "run_name": child.name,
            "target": extract_primary_target(record, default=child.name),
            "scan_mode": record.get("scan_mode") or "deep",
            "status": status,
            "start_time": start_time,
            "end_time": end_time,
            "duration": format_duration(start_time, end_time),
            "finished": bool(record.get("finished") or end_time or status in ("completed", "stopped", "failed", "interrupted")),
            "findings_count": len(findings),
            "severity_counts": sev_counts,
            "_mtime": mtime,
        })

    # Sort newest first
    scans.sort(key=lambda s: (s.get("start_time") or "", s["_mtime"]), reverse=True)
    return scans


def get_global_stats(tenant_id: str | None = None) -> dict[str, Any]:
    """Compute aggregate stats across available scans for the given tenant or platform."""
    scans = list_all_scans(tenant_id=tenant_id)
    total_scans = len(scans)
    active_scans = sum(1 for s in scans if s["status"] == "running")

    total_findings = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0

    all_findings: list[dict[str, Any]] = []
    for s in scans:
        sev = s.get("severity_counts", {})
        total_findings += sev.get("total", 0)
        critical_count += sev.get("critical", 0)
        high_count += sev.get("high", 0)
        medium_count += sev.get("medium", 0)
        low_count += sev.get("low", 0)
        info_count += sev.get("info", 0)

        # Pull findings for recent list (from up to 5 scans)
        if len(all_findings) < 20:
            detail = get_scan_findings(runs_base_dir() / s["run_id"])
            for f in detail:
                f["run_id"] = s["run_id"]
                all_findings.append(f)

    # Sort findings by severity
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "total_findings": total_findings,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "info_count": info_count,
        "recent_scans": scans[:6],
        "recent_findings": all_findings[:10],
    }
