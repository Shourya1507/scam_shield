"""ScamShield CLI — full-featured command-line interface.

Commands
────────
  scan          Scan a single piece of text/call/email for scam risk
  batch-scan    Scan a directory or list of files; write a JSON report
  export        Export the audit log in JSON or CSV format
  verify-audit  Verify the tamper-evident audit-log hash chain
  serve-webhook Start a local HTTP server that accepts webhook POSTs

Usage examples
──────────────
  scamshield scan --type email --file phishing.txt --sender bad@amaz0n.xyz
  scamshield batch-scan --type email --dir ./inbox --output report.json
  scamshield export --format csv --output audit.csv
  scamshield verify-audit
  scamshield serve-webhook --port 8080 --type call
"""
import argparse
import csv
import glob
import hashlib
import hmac
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ── Path bootstrap ────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from agents.guardian_agent import GuardianAgent
from security.audit_logger import AuditLogger


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _load_text(args) -> str | None:
    """Return text from --text or --file, or None if neither provided."""
    if getattr(args, "text", None):
        return args.text
    path = getattr(args, "file", None)
    if path:
        with open(path) as f:
            return f.read()
    return None


def _scan_one(guardian: GuardianAgent, user_id: str, input_type: str,
              text: str, sender: str | None = None) -> dict:
    return guardian.process(
        user_id=user_id, input_type=input_type, text=text, sender=sender
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Sub-command handlers
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_scan(args) -> None:
    text = _load_text(args)
    if not text:
        print("Provide --text or --file", file=sys.stderr)
        sys.exit(1)

    guardian = GuardianAgent(guardian_contact=args.guardian_contact)
    result = _scan_one(
        guardian,
        user_id=args.user_id,
        input_type=args.type,
        text=text,
        sender=getattr(args, "sender", None),
    )
    print(json.dumps(result, indent=2, default=str))


def cmd_batch_scan(args) -> None:
    """Scan every .txt file in --dir (or files in --files) and emit a report."""
    files: list[str] = []
    if args.dir:
        files = sorted(glob.glob(os.path.join(args.dir, "*.txt")))
    elif args.files:
        files = args.files
    else:
        print("Provide --dir or --files", file=sys.stderr)
        sys.exit(1)

    guardian = GuardianAgent(guardian_contact=args.guardian_contact)
    report: list[dict] = []
    high_risk_count = 0

    for fpath in files:
        with open(fpath) as f:
            text = f.read()
        result = _scan_one(
            guardian,
            user_id=args.user_id,
            input_type=args.type,
            text=text,
        )
        verdict = result["agent_result"]["risk"]["verdict"]
        score = result["agent_result"]["risk"]["final_score"]
        if verdict in ("HIGH_RISK_SCAM", "LIKELY_SCAM"):
            high_risk_count += 1
        report.append(
            {
                "file": os.path.basename(fpath),
                "verdict": verdict,
                "score": score,
                "notification_sent": result["notification"].get("notified", False),
            }
        )
        # Progress indicator
        print(f"  {os.path.basename(fpath):40s}  {verdict}  ({score}/100)")

    summary = {
        "total_scanned": len(files),
        "high_risk_count": high_risk_count,
        "scan_ts": time.time(),
        "results": report,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"\nReport written to {args.output}")
    else:
        print(json.dumps(summary, indent=2))


def cmd_export(args) -> None:
    """Export the audit log in JSON or CSV format."""
    logger = AuditLogger(path=args.log)
    entries = logger.tail(n=args.last) if args.last else _all_entries(args.log)

    if args.format == "json":
        out = json.dumps(entries, indent=2, default=str)
        if args.output:
            with open(args.output, "w") as f:
                f.write(out)
            print(f"Exported {len(entries)} entries → {args.output}")
        else:
            print(out)

    elif args.format == "csv":
        if not entries:
            print("No log entries found.")
            return
        fieldnames = ["ts", "event_type", "user_id", "hash", "prev_hash"]
        rows = [
            {
                "ts": e.get("ts"),
                "event_type": e.get("event_type"),
                "user_id": e.get("user_id"),
                "hash": e.get("hash"),
                "prev_hash": e.get("prev_hash"),
            }
            for e in entries
        ]
        dest = open(args.output, "w", newline="") if args.output else sys.stdout
        writer = csv.DictWriter(dest, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        if args.output:
            dest.close()
            print(f"Exported {len(rows)} rows → {args.output}")


def _all_entries(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    entries = []
    with open(path) as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def cmd_verify_audit(args) -> None:
    ok = AuditLogger(path=args.log).verify_chain()
    print("Audit chain intact:", ok)
    sys.exit(0 if ok else 1)


def cmd_serve_webhook(args) -> None:
    """
    Minimal HTTP server that accepts POST /webhook with a JSON body.

    Body schema:
      { "user_id": "...", "text": "...", "sender": "..." (optional) }

    Secured via HMAC-SHA256 if WEBHOOK_SECRET env var is set.
    """
    guardian = GuardianAgent(guardian_contact=args.guardian_contact)
    input_type = args.type
    secret = os.getenv("WEBHOOK_SECRET", "")

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            pass  # silence default access log

        def do_GET(self):
            if self.path in ("/", "/health", "/healthz"):
                resp_body = b'{"status":"healthy"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
            else:
                resp_body = b'{"error":"not_found"}'
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)

        def do_POST(self):
            if self.path != "/webhook":
                self.send_response(404)
                self.end_headers()
                return

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)

            # HMAC verification (optional)
            if secret:
                sig = self.headers.get("X-ScamShield-Signature", "")
                expected = hmac.new(
                    secret.encode(), body, hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(sig, expected):
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b'{"error":"invalid_signature"}')
                    return

            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error":"invalid_json"}')
                return

            result = guardian.process(
                user_id=payload.get("user_id", "webhook-anon"),
                input_type=input_type,
                text=payload.get("text", ""),
                sender=payload.get("sender"),
            )
            resp_body = json.dumps(result, default=str).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)

    server = HTTPServer(("0.0.0.0", args.port), _Handler)
    print(f"ScamShield webhook server listening on port {args.port} (type={input_type})")
    print("POST to http://localhost:{args.port}/webhook")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")


# ═══════════════════════════════════════════════════════════════════════════════
# Argument parser
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scamshield",
        description="ScamShield AI — multi-agent scam protection CLI",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────────
    scan = sub.add_parser("scan", help="Scan a single piece of content for scam risk")
    scan.add_argument("--type", choices=["call", "email", "financial"], required=True)
    scan.add_argument("--file", help="Path to a text file")
    scan.add_argument("--text", help="Inline text (alternative to --file)")
    scan.add_argument("--sender", help="Sender email address (for --type email)")
    scan.add_argument("--user-id", default="cli-user", dest="user_id")
    scan.add_argument("--guardian-contact", default="+1-555-0100", dest="guardian_contact")

    # ── batch-scan ────────────────────────────────────────────────────────────
    batch = sub.add_parser("batch-scan", help="Scan all .txt files in a directory")
    batch.add_argument("--type", choices=["call", "email", "financial"], required=True)
    batch.add_argument("--dir", help="Directory containing .txt files to scan")
    batch.add_argument("--files", nargs="+", help="Explicit list of files to scan")
    batch.add_argument("--output", "-o", help="Path to write JSON report")
    batch.add_argument("--user-id", default="batch-user", dest="user_id")
    batch.add_argument("--guardian-contact", default="+1-555-0100", dest="guardian_contact")

    # ── export ────────────────────────────────────────────────────────────────
    export = sub.add_parser("export", help="Export the audit log")
    export.add_argument("--format", choices=["json", "csv"], default="json")
    export.add_argument("--output", "-o", help="Output file path (stdout if omitted)")
    export.add_argument("--log", default="scamshield_audit.log", help="Audit log path")
    export.add_argument("--last", type=int, help="Export only the last N entries")

    # ── verify-audit ──────────────────────────────────────────────────────────
    va = sub.add_parser("verify-audit", help="Verify the audit log hash chain is intact")
    va.add_argument("--log", default="scamshield_audit.log")

    # ── serve-webhook ─────────────────────────────────────────────────────────
    wh = sub.add_parser("serve-webhook", help="Start a webhook HTTP endpoint")
    wh.add_argument("--type", choices=["call", "email", "financial"], required=True)
    wh.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8080)))
    wh.add_argument("--guardian-contact", default="+1-555-0100", dest="guardian_contact")

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    dispatch = {
        "scan": cmd_scan,
        "batch-scan": cmd_batch_scan,
        "export": cmd_export,
        "verify-audit": cmd_verify_audit,
        "serve-webhook": cmd_serve_webhook,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
