#!/usr/bin/env python3
"""
MCP Security Report Generator

Combines findings from analyze_code.py and/or check_config.py and/or
introspect_runtime.py into a structured Markdown security report.

Usage:
    python generate_report.py --findings findings.json --template full
    python generate_report.py --findings findings.json --template quick --output report.md
    python generate_report.py --findings rt.json --findings2 code.json --template full
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
SEVERITY_ICONS = {
    'CRITICAL': '🚨',
    'HIGH': '⚠️',
    'MEDIUM': '📋',
    'LOW': 'ℹ️',
    'INFO': 'ℹ️',
}

ROADMAP_TIMEFRAME = {
    'CRITICAL': ('🚨 Immediate (within 24 hours)',
                 '*These must be resolved before this server can be used in production.*'),
    'HIGH': ('⚠️ Short-term (within 1 week)', ''),
    'MEDIUM': ('📋 Medium-term (within 1 month)', ''),
    'LOW': ('ℹ️ Long-term (within 3 months)', ''),
}


def overall_risk_rating(summary: dict) -> str:
    if summary.get('critical', 0) > 0:
        return 'CRITICAL'
    if summary.get('high', 0) >= 2:
        return 'HIGH'
    if summary.get('high', 0) == 1 or summary.get('medium', 0) >= 3:
        return 'MEDIUM'
    if summary.get('medium', 0) > 0 or summary.get('low', 0) > 0:
        return 'LOW'
    return 'LOW'


def security_min_bar(findings: list[dict]) -> list[tuple[str, str, str]]:
    """
    Assess OWASP GenAI Dev Guide Security Minimum Bar from findings.
    Returns list of (control_area, status, note).
    """
    checks = [f['check'] for f in findings]
    vuln_ids = [f.get('vulnerability_id', '') for f in findings]

    def failed(check_names: list[str]) -> bool:
        return any(c in checks for c in check_names)

    auth_failed = 'authentication_absence' in checks or 'V05' in vuln_ids
    auth_partial = not auth_failed and any(v in vuln_ids for v in ['V06', 'V09', 'V16'])

    isolation_failed = any(v in vuln_ids for v in ['V25', 'V22'])
    tooling_failed = any(v in vuln_ids for v in ['V03', 'V11', 'V12', 'V14', 'V17'])
    validation_failed = any(v in vuln_ids for v in ['V01', 'V02', 'V10', 'V21'])
    deployment_failed = any(v in vuln_ids for v in ['V07', 'V08', 'V13', 'V23', 'V27', 'V28'])

    return [
        ('Strong Identity, Auth & Policy Enforcement',
         'FAIL' if auth_failed else ('PARTIAL' if auth_partial else 'PASS'),
         'Auth findings detected' if auth_failed else ''),
        ('Strict Isolation & Lifecycle Control',
         'FAIL' if isolation_failed else 'PASS',
         'Cross-tenant or context bleeding findings' if isolation_failed else ''),
        ('Trusted, Controlled Tooling',
         'FAIL' if tooling_failed else 'PASS',
         'Tool poisoning or rug pull findings' if tooling_failed else ''),
        ('Schema-Driven Validation Everywhere',
         'FAIL' if validation_failed else 'PASS',
         'Input validation findings detected' if validation_failed else ''),
        ('Hardened Deployment & Continuous Oversight',
         'FAIL' if deployment_failed else 'PASS',
         'Deployment configuration findings' if deployment_failed else ''),
    ]


# ---------------------------------------------------------------------------
# Full Audit Report (Template A)
# ---------------------------------------------------------------------------

def generate_full_report(all_findings: list[dict], context: dict) -> str:
    target = context.get('target', 'MCP Server')
    review_date = context.get('review_date', datetime.now(timezone.utc).strftime('%Y-%m-%d'))
    input_type = context.get('input_type', 'Mixed (Runtime + Static)')
    deployment = context.get('deployment', 'Unknown')

    # Sort findings: runtime first (MCP-RT-*), then static (MCP-FIND-*)
    rt_findings = [f for f in all_findings if f.get('finding_id', '').startswith('MCP-RT')]
    static_findings = [f for f in all_findings if not f.get('finding_id', '').startswith('MCP-RT')]

    # Assign IDs to static findings
    for i, f in enumerate(static_findings, 1):
        if not f.get('finding_id'):
            f['finding_id'] = f'MCP-FIND-{i:03d}'

    ordered_findings = rt_findings + static_findings

    # Summary counts
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for f in ordered_findings:
        sev = f.get('severity', 'INFO')
        counts[sev] = counts.get(sev, 0) + 1

    total = sum(counts.values())
    rating = overall_risk_rating(counts)
    min_bar = security_min_bar(ordered_findings)
    min_bar_pass = sum(1 for _, status, _ in min_bar if status == 'PASS')

    lines = [
        '# MCP Security Audit Report',
        '',
        f'**Target:** {target}',
        f'**Review Date:** {review_date}',
        f'**Reviewer:** Claude (MCP Security Review Skill v1.0)',
        f'**Input Type:** {input_type}',
        f'**Deployment Context:** {deployment}',
        '',
        '---',
        '',
        '## Executive Summary',
        '',
        f'**Overall Risk Rating:** {rating}',
        f'**Total Findings:** {total} ({counts["CRITICAL"]} Critical, {counts["HIGH"]} High, '
        f'{counts["MEDIUM"]} Medium, {counts["LOW"]} Low, {counts["INFO"]} Informational)',
        f'**Security Minimum Bar:** {"PASS" if min_bar_pass == 5 else "FAIL"} — {min_bar_pass}/5 checklist items passed',
        '',
    ]

    # Auto-generate executive summary text
    if counts['CRITICAL'] > 0:
        lines.append(
            f'This MCP server has **{counts["CRITICAL"]} Critical** finding(s) that require '
            f'immediate attention before deployment. The most serious issues include '
            f'{", ".join(f["description"][:60] for f in ordered_findings if f.get("severity") == "CRITICAL")[:150]}. '
            f'Do not use this server in production until Critical findings are resolved.'
        )
    elif counts['HIGH'] > 0:
        lines.append(
            f'This MCP server has **{counts["HIGH"]} High** severity finding(s) that present '
            f'significant security risk. These should be addressed within one week. '
            f'Deployment should be carefully considered given the identified risks.'
        )
    else:
        lines.append(
            f'This MCP server passed Critical and High severity checks. '
            f'{counts["MEDIUM"]} Medium and {counts["LOW"]} Low severity findings were identified '
            f'that should be addressed as part of ongoing security improvement.'
        )

    lines += [
        '',
        '---',
        '',
        '## Security Minimum Bar Checklist (OWASP GenAI Dev Guide)',
        '',
        '| # | Control Area | Status | Notes |',
        '|---|--------------|--------|-------|',
    ]

    for i, (area, status, note) in enumerate(min_bar, 1):
        status_icon = {'PASS': '✅', 'FAIL': '❌', 'PARTIAL': '⚠️', 'N/A': '—',
                       'CANNOT ASSESS': '❓'}.get(status, status)
        lines.append(f'| {i} | {area} | {status_icon} {status} | {note} |')

    lines += ['', '---', '']

    # Runtime findings section
    if rt_findings:
        lines += [
            '## §1 Runtime Manifest Findings (Mode 1)',
            '',
            '*Findings from the automatic runtime tool manifest scan.*',
            '',
        ]
        for f in sorted(rt_findings, key=lambda x: SEVERITY_ORDER.get(x.get('severity', 'INFO'), 5)):
            lines += _format_finding_block(f)
    else:
        lines += [
            '## §1 Runtime Manifest Findings (Mode 1)',
            '',
            '✅ No runtime manifest findings detected.',
            '',
        ]

    lines += ['---', '']

    # Static findings section
    if static_findings:
        lines += [
            '## §2 Static Code / Config Findings (Mode 2)',
            '',
            '*Findings from static analysis of provided source code or configuration.*',
            '',
        ]
        for f in sorted(static_findings, key=lambda x: SEVERITY_ORDER.get(x.get('severity', 'INFO'), 5)):
            lines += _format_finding_block(f)
    elif not rt_findings:
        lines += ['## §2 Static Code / Config Findings (Mode 2)', '', 'No findings.', '']

    lines += ['---', '']

    # Framework coverage
    lines += [
        '## Framework Coverage Summary',
        '',
        '| Framework | Items Checked | Findings Mapped |',
        '|-----------|--------------|-----------------|',
    ]
    adversa_mapped = len([f for f in ordered_findings if f.get('adversa_rank')])
    owasp_mapped = len([f for f in ordered_findings if f.get('owasp_mcp')])
    lines += [
        f'| Adversa AI Top 25 | 25 | {adversa_mapped} |',
        f'| OWASP MCP Top 10 | 10 | {owasp_mapped} |',
        f'| OWASP GenAI Dev Guide | 8 domains | {len([f for f in ordered_findings if f.get("dev_guide_section")])} |',
        f'| OWASP GenAI Cheat Sheet | 6 areas | (consumer-side guidance applied) |',
        '',
        '---',
        '',
    ]

    # Remediation roadmap
    lines += ['## Prioritized Remediation Roadmap', '']

    roadmap_groups: dict[str, list[dict]] = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
    for f in ordered_findings:
        sev = f.get('severity', 'INFO')
        if sev in roadmap_groups:
            roadmap_groups[sev].append(f)

    for severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        group = roadmap_groups[severity]
        if group:
            title, subtitle = ROADMAP_TIMEFRAME[severity]
            lines.append(f'### {title}')
            if subtitle:
                lines.append(subtitle)
            lines.append('')
            for f in group:
                fid = f.get('finding_id', '?')
                desc = f.get('description', '')[:80]
                lines.append(f'- [ ] **[{fid}]** {desc}')
            lines.append('')

    # Long-term architecture items
    lines += [
        '### 🏗️ Long-term (within 3 months)',
        '',
        '- [ ] Establish MCP server governance registry and approval workflow (C21)',
        '- [ ] Implement Human-in-the-Loop (HITL) gates for sensitive tool invocations (C16)',
        '- [ ] Set up continuous tool manifest monitoring with mcp-watch',
        '- [ ] Integrate `invariantlabs/mcp-scan` into CI/CD pipeline',
        '- [ ] Achieve full Security Minimum Bar compliance',
        '',
        '---',
        '',
    ]

    # What was not assessed
    lines += [
        '## What Was Not Assessed',
        '',
        '- **Runtime behavior** — only static analysis was performed; dynamic testing was not conducted.',
        '- **Network configuration** — deployment infrastructure may not have been fully reviewed.',
        '- **Authentication backend** — external identity providers were not validated.',
        '- **Third-party dependencies** — transitive dependency vulnerabilities may not be fully covered.',
        '',
    ]

    return '\n'.join(lines)


def _format_finding_block(f: dict) -> list[str]:
    """Format a single finding as Markdown."""
    fid = f.get('finding_id', '?')
    title = f.get('description', f.get('type', 'Finding'))[:80]
    severity = f.get('severity', 'INFO')
    icon = SEVERITY_ICONS.get(severity, '•')

    lines = [
        f'### [{fid}] {icon} {title}',
        '',
        '| Field | Value |',
        '|-------|-------|',
        f'| Severity | **{severity}** |',
    ]

    component_fields = [
        ('Component / Tool', f.get('tool_name') or f.get('affected_component', '')),
        ('Server', f.get('server', '')),
        ('File', f'{f.get("file", "")}:{f.get("line", "")}' if f.get('file') and f.get('line') else f.get('file', '')),
        ('Config Path', f.get('json_path', '')),
        ('Adversa AI Rank', f'#{f["adversa_rank"]}' if f.get('adversa_rank') else ''),
        ('OWASP MCP Top 10', f.get('owasp_mcp', '')),
        ('Dev Guide Section', f.get('dev_guide_section', '')),
        ('Vulnerability ID', f.get('vulnerability_id', '')),
        ('Effort to Fix', f.get('effort_to_fix', '')),
    ]

    for label, value in component_fields:
        if value:
            lines.append(f'| {label} | {value} |')

    evidence = f.get('evidence') or f.get('snippet', '')
    recommendation = f.get('recommendation', '')

    lines += ['']
    if evidence:
        lines += [f'**Evidence:**', f'> {evidence}', '']
    if recommendation:
        lines += [f'**Recommendation:** {recommendation}', '']

    lines.append('---')
    lines.append('')
    return lines


# ---------------------------------------------------------------------------
# Quick Risk Assessment (Template B)
# ---------------------------------------------------------------------------

def generate_quick_report(all_findings: list[dict], context: dict) -> str:
    target = context.get('target', 'MCP Server')
    review_date = context.get('review_date', datetime.now(timezone.utc).strftime('%Y-%m-%d'))

    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for f in all_findings:
        sev = f.get('severity', 'INFO')
        counts[sev] = counts.get(sev, 0) + 1

    rating = overall_risk_rating(counts)

    lines = [
        '# MCP Quick Risk Assessment',
        '',
        f'**Target:** {target}',
        f'**Date:** {review_date}',
        f'**Input:** {context.get("input_type", "Description / Limited Info")}',
        f'**Assessment Type:** Quick Assessment',
        '',
        '---',
        '',
        f'## Preliminary Risk Rating: {rating}',
        '',
        f'*{counts["CRITICAL"]} Critical, {counts["HIGH"]} High, '
        f'{counts["MEDIUM"]} Medium, {counts["LOW"]} Low findings.*',
        '',
        '---',
        '',
        '## Key Risk Areas',
        '',
    ]

    for f in sorted(all_findings, key=lambda x: SEVERITY_ORDER.get(x.get('severity', 'INFO'), 5)):
        sev = f.get('severity', 'INFO')
        icon = SEVERITY_ICONS.get(sev, '•')
        desc = f.get('description', '')[:120]
        rec = f.get('recommendation', '')[:200]
        owasp = f.get('owasp_mcp', '')
        adversa = f.get('adversa_rank', '')
        lines += [
            f'### {icon} [{sev}] {desc}',
            '',
            f'**Framework:** Adversa #{adversa} | {owasp}' if adversa else f'**Framework:** {owasp}',
            f'**Recommendation:** {rec}',
            '',
        ]

    lines += [
        '---',
        '',
        '## Consumer-Side Checklist (OWASP GenAI Cheat Sheet)',
        '',
        'Before using this MCP server:',
        '- [ ] **Verify source** — Is this from a trusted, known publisher?',
        '- [ ] **Check version pinning** — Is the version pinned and hash-verified?',
        '- [ ] **Review tool descriptions** — Have tool definitions been scanned for injection patterns?',
        '- [ ] **Assess token scopes** — Are OAuth scopes limited to what is actually needed?',
        '- [ ] **Establish governance** — Is this server in your approved MCP registry?',
        '- [ ] **Plan for revocation** — Can you quickly disconnect this server if needed?',
        '',
        '---',
        '',
        '## Recommended Next Steps',
        '',
        '1. Address all Critical and High findings before using this server in production.',
        '2. Share source code or a GitHub link for a full security audit (Mode 2).',
        '3. Pin the server version and verify its hash before connecting.',
        '',
        '*For a definitive security assessment, share the server\'s source code or GitHub link '
        'to enable a Full Audit Report.*',
    ]

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def load_findings_file(path: str) -> list[dict]:
    """Load findings from a JSON file produced by analyze_code.py, check_config.py, or introspect_runtime.py."""
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as e:
        print(f"Error loading {path}: {e}", file=sys.stderr)
        sys.exit(1)

    findings = data.get('findings', [])
    if not isinstance(findings, list):
        print(f"Error: {path} does not contain a 'findings' list", file=sys.stderr)
        sys.exit(1)
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description='MCP Security Report Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--findings', metavar='FILE', required=True,
                        help='Primary findings JSON (from any scanner script)')
    parser.add_argument('--findings2', metavar='FILE',
                        help='Secondary findings JSON to merge (e.g., combine runtime + static)')
    parser.add_argument('--template', choices=['full', 'quick'], default='full',
                        help='Report template: full (default) or quick')
    parser.add_argument('--output', metavar='FILE',
                        help='Write Markdown report to file (default: stdout)')
    parser.add_argument('--target', default='MCP Server',
                        help='Target MCP server name/description for report header')
    parser.add_argument('--input-type', default='Mixed',
                        help='Input type description for report header')
    parser.add_argument('--deployment', default='Unknown',
                        help='Deployment context (local/remote/multi-tenant)')
    args = parser.parse_args()

    all_findings = load_findings_file(args.findings)
    if args.findings2:
        all_findings += load_findings_file(args.findings2)

    context = {
        'target': args.target,
        'review_date': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
        'input_type': args.input_type,
        'deployment': args.deployment,
    }

    if args.template == 'quick':
        report = generate_quick_report(all_findings, context)
    else:
        report = generate_full_report(all_findings, context)

    if args.output:
        Path(args.output).write_text(report, encoding='utf-8')
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report)


if __name__ == '__main__':
    main()
