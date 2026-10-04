"""Flask Application factory and routes for iqAudi360 Web GUI."""

from __future__ import annotations

import io
import json
import logging
import os
import queue
import sys
import time
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from strix.config import load_settings
from strix.core.paths import run_dir_for, runs_base_dir
from strix.gui.auth import (
    ROLE_ADMIN,
    ROLE_CLIENT,
    ROLE_DEV,
    ROLE_SUPERADMIN,
    init_auth,
    require_auth,
    require_role,
    require_tenant_scan_access,
)
from strix.gui.auth.db import log_audit_event
from strix.gui.data import (
    get_global_stats,
    get_scan_detail,
    list_all_scans,
)
from strix.gui.scanner import ScanManager
from flask import g

logger = logging.getLogger(__name__)


def create_app() -> Flask:
    """Create and configure the Flask web application."""
    gui_dir = Path(__file__).resolve().parent
    template_dir = gui_dir / "templates"
    static_dir = gui_dir / "static"

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir),
    )
    app.config["SECRET_KEY"] = os.environ.get("IQAUDI360_SECRET_KEY", "iqaudi360_enterprise_secret_key_2026")
    app.config["JSON_SORT_KEYS"] = False

    # Initialize Auth, RBAC, Firebase Admin SDK & Multi-Tenant DB
    init_auth(app)

    scan_mgr = ScanManager.get_instance()

    # Template filters
    @app.template_filter("time_format")
    def time_format_filter(iso_str: str | None) -> str:
        if not iso_str:
            return "N/A"
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            return dt.strftime("%b %d, %Y %H:%M:%S UTC")
        except Exception:
            return str(iso_str)

    # Routes

    @app.route("/")
    @require_auth
    def dashboard() -> str:
        """Main dashboard view."""
        tenant_id = None if g.is_superadmin else (g.current_tenant.get("tenant_id") if g.current_tenant else None)
        stats = get_global_stats(tenant_id=tenant_id)
        
        # Filter active jobs
        active_jobs = scan_mgr.list_jobs()
        if not g.is_superadmin and tenant_id:
            active_jobs = [j for j in active_jobs if j.get("options", {}).get("tenant_id") == tenant_id or j.get("job_id") in [s["run_id"] for s in stats.get("recent_scans", [])]]

        return render_template(
            "dashboard.html",
            stats=stats,
            active_jobs=active_jobs,
            page="dashboard",
        )

    @app.route("/new")
    @require_auth
    @require_role(ROLE_SUPERADMIN, ROLE_ADMIN, ROLE_DEV)
    def new_scan() -> str:
        """New scan configuration form."""
        return render_template("new_scan.html", page="new_scan")

    @app.route("/scans")
    @require_auth
    def scans_list() -> str:
        """History of scans scoped to current tenant."""
        tenant_id = None if g.is_superadmin else (g.current_tenant.get("tenant_id") if g.current_tenant else None)
        scans = list_all_scans(tenant_id=tenant_id)
        active_jobs = scan_mgr.list_jobs()
        if not g.is_superadmin and tenant_id:
            active_jobs = [j for j in active_jobs if j.get("options", {}).get("tenant_id") == tenant_id]

        return render_template(
            "scans_list.html",
            scans=scans,
            active_jobs=active_jobs,
            page="scans",
        )

    @app.route("/findings")
    @require_auth
    def findings_catalog() -> str:
        """Consolidated findings across accessible scans."""
        tenant_id = None if g.is_superadmin else (g.current_tenant.get("tenant_id") if g.current_tenant else None)
        stats = get_global_stats(tenant_id=tenant_id)
        scans = list_all_scans(tenant_id=tenant_id)
        return render_template(
            "findings_list.html",
            findings=stats["recent_findings"],
            scans=scans,
            page="findings",
        )

    @app.route("/reports")
    @require_auth
    def reports_catalog() -> str:
        """Available scan reports for current tenant."""
        tenant_id = None if g.is_superadmin else (g.current_tenant.get("tenant_id") if g.current_tenant else None)
        scans = list_all_scans(tenant_id=tenant_id)
        return render_template(
            "reports_list.html",
            scans=scans,
            page="reports",
        )

    @app.route("/settings")
    @require_auth
    @require_role(ROLE_SUPERADMIN)
    def settings_view() -> str:
        """System and environment settings/diagnostics."""
        from strix.interface.cli_args import get_version
        settings = load_settings()

        # Check Docker status safely
        docker_available = False
        docker_version = "Unavailable"
        try:
            import docker
            client = docker.from_env(timeout=2)
            version_info = client.version()
            docker_available = True
            docker_version = f"{version_info.get('Version', 'OK')} ({version_info.get('Platform', {}).get('Name', 'Docker')})"
        except Exception as exc:
            docker_version = f"Error: {exc}"

        # Mask sensitive LLM info
        raw_model = settings.llm.model or "Not Configured"
        api_base = settings.llm.api_base or "Default"
        raw_image = settings.runtime.image or "ghcr.io/iqaudi360/sandbox:1.3.0"
        sandbox_image = "iqAudi360 Autonomous Security Sandbox v1.3.0" if "strix" in raw_image.lower() else raw_image
        runs_dir = str(runs_base_dir().resolve())

        info = {
            "version": get_version(),
            "python_version": sys.version.split()[0],
            "platform": sys.platform,
            "docker_available": docker_available,
            "docker_version": docker_version,
            "llm_model": raw_model,
            "api_base": api_base,
            "sandbox_image": sandbox_image,
            "runs_directory": runs_dir,
            "default_timeout": settings.llm.timeout,
        }
        return render_template("settings.html", info=info, page="settings")

    @app.route("/scan/<scan_id>")
    @require_auth
    @require_tenant_scan_access
    def scan_view(scan_id: str) -> Any:
        """Live scan progress or completed scan results."""
        # 1. Check if it's an active in-memory job
        job = scan_mgr.get_job(scan_id)
        if job and job.status in ("starting", "running"):
            return render_template(
                "live_scan.html",
                scan_id=scan_id,
                job=job.to_dict(),
                page="scans",
            )

        # 2. Check if it exists on disk
        target_name = job.run_name if (job and job.run_name) else scan_id
        detail = get_scan_detail(target_name)
        if detail:
            return render_template(
                "scan_results.html",
                scan=detail,
                page="scans",
            )

        # 3. If job finished but directory name might be different
        if job:
            return render_template(
                "live_scan.html",
                scan_id=scan_id,
                job=job.to_dict(),
                page="scans",
            )

        flash(f"Scan '{scan_id}' not found.", "error")
        return redirect(url_for("scans_list"))

    # API Endpoints

    @app.route("/api/scans/start", methods=["POST"])
    @require_auth
    @require_role(ROLE_SUPERADMIN, ROLE_ADMIN, ROLE_DEV)
    def api_start_scan() -> Any:
        """API to launch a background scan."""
        data = request.get_json(silent=True) or request.form.to_dict()

        target = (data.get("target") or "").strip()
        if not target:
            return jsonify({"ok": False, "error": "Target is required."}), 400

        # Enforce authorization agreement
        authorized = data.get("authorized")
        if not authorized or str(authorized).lower() not in ("true", "1", "yes", "on"):
            return jsonify({
                "ok": False,
                "error": "You must certify that you are authorized to test the target system.",
            }), 400

        scan_mode = data.get("scan_mode", "deep").lower()
        if scan_mode not in ("quick", "standard", "deep"):
            scan_mode = "deep"

        scope_mode = data.get("scope_mode", "auto").lower()
        if scope_mode not in ("auto", "diff", "full"):
            scope_mode = "auto"

        options: dict[str, Any] = {}
        if data.get("max_budget"):
            try:
                options["max_budget_usd"] = float(data["max_budget"])
            except ValueError:
                pass

        if data.get("max_turns"):
            try:
                options["max_turns"] = int(data["max_turns"])
            except ValueError:
                pass

        if data.get("instruction"):
            options["instruction"] = str(data["instruction"]).strip()

        if data.get("instruction_file"):
            options["instruction_file"] = str(data["instruction_file"]).strip()

        if data.get("workspace_file"):
            options["workspace_file"] = str(data["workspace_file"]).strip()

        if data.get("diff_base"):
            options["diff_base"] = str(data["diff_base"]).strip()

        if data.get("config"):
            options["config"] = str(data["config"]).strip()

        if data.get("mcp_config"):
            options["mcp_config"] = str(data["mcp_config"]).strip()

        tenant_id = g.current_tenant.get("tenant_id") if g.current_tenant else "org_default"
        user_id = g.user.get("user_id") if g.user else "system"

        try:
            job = scan_mgr.start_scan(
                target=target,
                scan_mode=scan_mode,
                scope_mode=scope_mode,
                options=options,
                tenant_id=tenant_id,
                created_by=user_id,
            )

            log_audit_event(
                actor_user_id=user_id,
                actor_email=g.user.get("email"),
                tenant_id=tenant_id,
                action="scan_start",
                resource_type="scan",
                resource_id=job.job_id,
                result="success",
                details=f"Target: {target}, Mode: {scan_mode}",
            )

            return jsonify({
                "ok": True,
                "job_id": job.job_id,
                "target": job.target,
                "scan_mode": job.scan_mode,
                "redirect_url": url_for("scan_view", scan_id=job.job_id),
            })
        except Exception as exc:
            logger.exception("Failed to start scan")
            import re
            err_text = re.sub(r"(?i)strix", "iqAudi360", str(exc))
            return jsonify({"ok": False, "error": f"iqAudi360 scan engine error: {err_text}"}), 500

    @app.route("/api/scans/<scan_id>/stop", methods=["POST"])
    @require_auth
    @require_role(ROLE_SUPERADMIN, ROLE_ADMIN, ROLE_DEV)
    @require_tenant_scan_access
    def api_stop_scan(scan_id: str) -> Any:
        """API to terminate an active scan."""
        success = scan_mgr.stop_scan(scan_id)
        if success:
            log_audit_event(
                actor_user_id=g.user.get("user_id"),
                actor_email=g.user.get("email"),
                tenant_id=g.current_tenant.get("tenant_id") if g.current_tenant else None,
                action="scan_stop",
                resource_type="scan",
                resource_id=scan_id,
                result="success",
            )
            return jsonify({"ok": True, "message": "Scan stopped successfully."})
        return jsonify({"ok": False, "error": "Could not stop scan. It may already be finished."}), 400

    @app.route("/api/scans/<scan_id>")
    @require_auth
    @require_tenant_scan_access
    def api_scan_detail(scan_id: str) -> Any:
        """API returning current scan details / status."""
        job = scan_mgr.get_job(scan_id)
        target_name = job.run_name if (job and job.run_name) else scan_id
        detail = get_scan_detail(target_name)

        if detail:
            return jsonify({"ok": True, "scan": detail})

        if job:
            return jsonify({
                "ok": True,
                "scan": {
                    "run_id": job.job_id,
                    "target": job.target,
                    "scan_mode": job.scan_mode,
                    "status": job.status,
                    "start_time": job.start_time,
                    "end_time": job.end_time,
                    "finished": job.status in ("completed", "stopped", "failed"),
                    "findings": [],
                    "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
                    "agents": [],
                    "log_lines": job.logs[-100:],
                },
            })

        return jsonify({"ok": False, "error": "Scan not found"}), 404

    @app.route("/api/scans/<scan_id>/stream")
    @require_auth
    @require_role(ROLE_SUPERADMIN, ROLE_ADMIN, ROLE_DEV)
    @require_tenant_scan_access
    def api_scan_stream(scan_id: str) -> Response:
        """Server-Sent Events (SSE) real-time feed for scan logs and status."""
        job = scan_mgr.get_job(scan_id)

        def event_generator() -> Any:
            yield "data: {\"type\": \"connected\"}\n\n"

            if not job:
                # Scan might already be finished on disk
                detail = get_scan_detail(scan_id)
                if detail:
                    yield f"data: {json.dumps({'type': 'status', 'status': detail['status'], 'finished': True})}\n\n"
                    for line in detail.get("log_lines", [])[-50:]:
                        yield f"data: {json.dumps({'type': 'log', 'line': line})}\n\n"
                return

            subscriber_q = job.add_subscriber()
            try:
                last_ping = time.time()
                while True:
                    try:
                        # Non-blocking get with timeout
                        event = subscriber_q.get(timeout=1.0)
                        yield f"data: {json.dumps(event)}\n\n"
                    except queue.Empty:
                        pass

                    # Periodic ping to keep HTTP connection alive
                    now = time.time()
                    if now - last_ping > 15:
                        yield ": ping\n\n"
                        last_ping = now

                    # Periodically check agents and findings from disk if run_name is resolved
                    if job.run_name:
                        run_dir = run_dir_for(job.run_name)
                        if run_dir.is_dir():
                            from strix.gui.data import parse_agents_from_run, get_scan_findings, calculate_severity_counts
                            agents = parse_agents_from_run(run_dir)
                            findings = get_scan_findings(run_dir)
                            sev_counts = calculate_severity_counts(findings)
                            yield f"data: {json.dumps({'type': 'progress', 'agents': agents, 'findings_count': len(findings), 'severity_counts': sev_counts, 'run_name': job.run_name})}\n\n"

                    # If job is terminal and queue is empty, exit stream
                    if job.status in ("completed", "stopped", "failed") and subscriber_q.empty():
                        yield f"data: {json.dumps({'type': 'status', 'status': job.status, 'finished': True, 'run_name': job.run_name or job.job_id})}\n\n"
                        break
            finally:
                job.remove_subscriber(subscriber_q)

        return Response(
            event_generator(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    # Report Downloads

    @app.route("/api/scans/<scan_id>/download/sarif")
    @require_auth
    @require_tenant_scan_access
    def download_sarif(scan_id: str) -> Any:
        """Download raw findings.sarif."""
        job = scan_mgr.get_job(scan_id)
        target_name = job.run_name if (job and job.run_name) else scan_id
        run_dir = run_dir_for(target_name)
        sarif_file = run_dir / "findings.sarif"
        if not sarif_file.is_file():
            abort(404, "SARIF report not generated for this scan.")

        log_audit_event(
            actor_user_id=g.user.get("user_id"),
            actor_email=g.user.get("email"),
            tenant_id=g.current_tenant.get("tenant_id") if g.current_tenant else None,
            action="report_download",
            resource_type="sarif",
            resource_id=scan_id,
            result="success",
        )
        return send_file(
            str(sarif_file),
            as_attachment=True,
            download_name=f"findings-{target_name}.sarif",
            mimetype="application/json",
        )

    @app.route("/api/scans/<scan_id>/download/coverage")
    @require_auth
    @require_tenant_scan_access
    def download_coverage(scan_id: str) -> Any:
        """Download raw coverage.json."""
        job = scan_mgr.get_job(scan_id)
        target_name = job.run_name if (job and job.run_name) else scan_id
        run_dir = run_dir_for(target_name)
        cov_file = run_dir / "coverage.json"
        if not cov_file.is_file():
            abort(404, "Coverage report not found.")

        log_audit_event(
            actor_user_id=g.user.get("user_id"),
            actor_email=g.user.get("email"),
            tenant_id=g.current_tenant.get("tenant_id") if g.current_tenant else None,
            action="report_download",
            resource_type="coverage",
            resource_id=scan_id,
            result="success",
        )
        return send_file(
            str(cov_file),
            as_attachment=True,
            download_name=f"coverage-{target_name}.json",
            mimetype="application/json",
        )

    @app.route("/api/scans/<scan_id>/download/json")
    @require_auth
    @require_tenant_scan_access
    def download_json(scan_id: str) -> Any:
        """Download vulnerabilities.json or combined scan JSON."""
        job = scan_mgr.get_job(scan_id)
        target_name = job.run_name if (job and job.run_name) else scan_id
        run_dir = run_dir_for(target_name)

        log_audit_event(
            actor_user_id=g.user.get("user_id"),
            actor_email=g.user.get("email"),
            tenant_id=g.current_tenant.get("tenant_id") if g.current_tenant else None,
            action="report_download",
            resource_type="json",
            resource_id=scan_id,
            result="success",
        )

        vuln_file = run_dir / "vulnerabilities.json"
        if vuln_file.is_file():
            return send_file(
                str(vuln_file),
                as_attachment=True,
                download_name=f"vulnerabilities-{target_name}.json",
                mimetype="application/json",
            )

        detail = get_scan_detail(target_name)
        if detail:
            return Response(
                json.dumps(detail, indent=2, default=str),
                mimetype="application/json",
                headers={"Content-Disposition": f"attachment; filename=scan-{target_name}.json"},
            )

        abort(404, "Scan data not found.")

    @app.route("/api/scans/<scan_id>/download/report")
    @require_auth
    @require_tenant_scan_access
    def download_markdown_report(scan_id: str) -> Any:
        """Download executive penetration test markdown report."""
        job = scan_mgr.get_job(scan_id)
        target_name = job.run_name if (job and job.run_name) else scan_id
        run_dir = run_dir_for(target_name)
        report_file = run_dir / "penetration_test_report.md"
        if not report_file.is_file():
            abort(404, "Markdown report not generated for this scan.")

        log_audit_event(
            actor_user_id=g.user.get("user_id"),
            actor_email=g.user.get("email"),
            tenant_id=g.current_tenant.get("tenant_id") if g.current_tenant else None,
            action="report_download",
            resource_type="markdown_report",
            resource_id=scan_id,
            result="success",
        )
        return send_file(
            str(report_file),
            as_attachment=True,
            download_name=f"report-{target_name}.md",
            mimetype="text/markdown",
        )

    @app.route("/api/scans/<scan_id>/download/pdf")
    @require_auth
    @require_tenant_scan_access
    def download_pdf_report(scan_id: str) -> Any:
        """Download professionally generated PDF report."""
        job = scan_mgr.get_job(scan_id)
        target_name = job.run_name if (job and job.run_name) else scan_id
        run_dir = run_dir_for(target_name)
        if not run_dir.is_dir():
            abort(404, "Scan directory not found.")

        try:
            from strix.interface.viewer.report_pdf import generate_report_pdf
            pdf_bytes = generate_report_pdf(run_dir)
            log_audit_event(
                actor_user_id=g.user.get("user_id"),
                actor_email=g.user.get("email"),
                tenant_id=g.current_tenant.get("tenant_id") if g.current_tenant else None,
                action="report_download",
                resource_type="pdf_report",
                resource_id=scan_id,
                result="success",
            )
            return send_file(
                io.BytesIO(pdf_bytes),
                as_attachment=True,
                download_name=f"iqaudi360-report-{target_name}.pdf",
                mimetype="application/pdf",
            )
        except Exception as exc:
            logger.exception("Failed to generate PDF report")
            abort(500, f"Failed to generate PDF report: {exc}")

    return app
