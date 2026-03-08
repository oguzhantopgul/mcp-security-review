#!/usr/bin/env python3
"""
MCP Runtime Tool Manifest Scanner — Mode 1

Scans a JSON dump of an MCP tool manifest for security indicators:
tool poisoning, Unicode anomalies, credential exposure, schema manipulation,
overbroad permissions, and tool shadowing.

This script serves two purposes:
1. As a standalone CLI tool accepting a JSON manifest dump (CI/CD, offline auditing)
2. As the canonical specification for Claude's mental Mode 1 checklist

Usage:
    python introspect_runtime.py --manifest tools.json
    python introspect_runtime.py --manifest tools.json --output report.md
    python introspect_runtime.py --stdin
    cat tools.json | python introspect_runtime.py --stdin
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# RT-CHECK-01: Tool Description Poisoning — Injection Trigger Phrases
# ---------------------------------------------------------------------------

INJECTION_CRITICAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'ignore\s+(all\s+)?previous\s+instructions', re.I), 'ignore previous instructions'),
    (re.compile(r'disregard\s+your', re.I), 'disregard your'),
    (re.compile(r'your\s+true\s+purpose', re.I), 'your true purpose'),
    (re.compile(r'do\s+not\s+(tell|inform)\s+the\s+user', re.I), 'do not tell the user'),
    (re.compile(r'do\s+not\s+reveal', re.I), 'do not reveal'),
    (re.compile(r'hidden\s+instructions?', re.I), 'hidden instructions'),
    (re.compile(r'secret\s+task', re.I), 'secret task'),
    (re.compile(r'(?m)^system\s*:', re.I), 'system: (at line start)'),
    (re.compile(r'(?m)^assistant\s*:', re.I), 'assistant: (at line start)'),
    (re.compile(r'\{\{.*?\}\}', re.DOTALL), 'template injection {{...}}'),
    (re.compile(r'<\|.*?\|>', re.DOTALL), 'model control token <|...|>'),
    (re.compile(r'\bOVERRIDE\b'), 'OVERRIDE (all-caps)'),
    (re.compile(r'\bIGNORE\b'), 'IGNORE (all-caps)'),
    (re.compile(r'\bjailbreak\b', re.I), 'jailbreak'),
    (re.compile(r'\bDAN\s+mode\b', re.I), 'DAN mode'),
    (re.compile(r'developer\s+mode\s+enabled', re.I), 'developer mode enabled'),
    (re.compile(r'pretend\s+(you\s+are|to\s+be)\s+an?\s+AI\s+without', re.I), 'pretend to be AI without'),
]

INJECTION_HIGH_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\balways\b.{0,30}\b(do|send|call|use|ignore|hide|forward|exfiltrate)\b', re.I), 'always + imperative verb'),
    (re.compile(r'\bnever\s+(tell|reveal|share|inform)\b', re.I), 'never tell/reveal/share'),
    (re.compile(r'\bmake\s+sure\s+to\b', re.I), 'make sure to'),
    (re.compile(r'\byou\s+must\b', re.I), 'you must'),
    (re.compile(r'(?m)^important\s*:', re.I), 'important: (at line start)'),
    (re.compile(r'\binstead\b', re.I), 'instead'),
    (re.compile(r'\bactually\b', re.I), 'actually'),
    (re.compile(r'\byour\s+(real|actual|true)\s+(goal|purpose|task|job|mission)\b', re.I), 'your real/true purpose'),
    (re.compile(r'\bwithout\s+(telling|informing|notifying)\s+the\s+user\b', re.I), 'without telling the user'),
    (re.compile(r'\bsilently\b', re.I), 'silently'),
    (re.compile(r'\bcovertly\b', re.I), 'covertly'),
    (re.compile(r'\bin\s+the\s+background\b', re.I), 'in the background'),
    # Note: bare 'instead' and 'actually' removed — too common in legitimate technical
    # descriptions to be useful signals at the two-or-more threshold (F003).
]

# ---------------------------------------------------------------------------
# RT-CHECK-02: Unicode Anomaly Detection
# ---------------------------------------------------------------------------

ZERO_WIDTH_CHARS: set[str] = {
    '\u200B',  # ZERO WIDTH SPACE
    '\u200C',  # ZERO WIDTH NON-JOINER
    '\u200D',  # ZERO WIDTH JOINER
    '\uFEFF',  # ZERO WIDTH NO-BREAK SPACE (BOM)
    '\u00AD',  # SOFT HYPHEN
}

DIRECTION_OVERRIDE_CHARS: set[str] = {
    '\u202E',  # RIGHT-TO-LEFT OVERRIDE
    '\u202D',  # LEFT-TO-RIGHT OVERRIDE
    '\u2066',  # LEFT-TO-RIGHT ISOLATE
    '\u2067',  # RIGHT-TO-LEFT ISOLATE
    '\u2068',  # FIRST STRONG ISOLATE
    '\u2069',  # POP DIRECTIONAL ISOLATE
}

CYRILLIC_HOMOGLYPH_MAP: dict[str, str] = {
    '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'r',
    '\u0441': 'c', '\u0445': 'x', '\u0456': 'i',
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041C': 'M',
    '\u041E': 'O', '\u0420': 'R', '\u0421': 'C', '\u0422': 'T',
    '\u0425': 'X',
}

# ---------------------------------------------------------------------------
# RT-CHECK-04: Credential & URL Exposure Patterns
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r'sk-[A-Za-z0-9]{32,}'), 'OpenAI API Key', 'HIGH'),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), 'GitHub Personal Access Token', 'HIGH'),
    (re.compile(r'ghs_[A-Za-z0-9]{36}'), 'GitHub Server Token', 'HIGH'),
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'AWS Access Key ID', 'HIGH'),
    (re.compile(r'xox[baprs]-[0-9]{10,}-[A-Za-z0-9-]+'), 'Slack Token', 'HIGH'),
    (re.compile(r'ya29\.[A-Za-z0-9_-]{50,}'), 'Google OAuth Token', 'HIGH'),
    (re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*'), 'Bearer Token', 'HIGH'),
    (re.compile(r'https?://[^:\s/]+:[^@\s/]+@[^\s]+'), 'URL with Embedded Credentials', 'HIGH'),
    (re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'), 'Possible Base64 Secret (>40 chars)', 'MEDIUM'),
]

SUSPICIOUS_URL_DOMAINS: set[str] = {
    'ngrok.io', 'ngrok-free.app', 'ngrok.app',
    'trycloudflare.com', 'cloudflare-ipfs.com',
    'serveo.net', 'localhost.run',
    'replit.dev', 'repl.co',
    'glitch.me', 'glitch.io',
    'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'rb.gy',
}

SUSPICIOUS_URL_PATTERN = re.compile(
    r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' +
    '|'.join(re.escape(d) for d in SUSPICIOUS_URL_DOMAINS) + r')',
    re.I,
)

# ---------------------------------------------------------------------------
# RT-CHECK-05: Capability Keywords
# ---------------------------------------------------------------------------

CAPABILITY_KEYWORDS: dict[str, list[str]] = {
    'filesystem': ['file', 'filesystem', 'read file', 'write file', 'directory',
                   'folder', 'path', 'disk', 'storage', 'open file', 'save file'],
    'shell_exec': ['execute', 'run command', 'shell', 'bash', 'terminal',
                   'subprocess', 'system call', 'script', 'command line',
                   'invoke process', 'spawn', 'run program'],
    'network':    ['http request', 'fetch url', 'download', 'upload', 'webhook',
                   'any url', 'arbitrary endpoint', 'outbound request', 'api call',
                   'http get', 'http post', 'curl', 'request url'],
    'database':   ['sql', 'query database', 'table', 'record', 'schema', 'database',
                   'postgres', 'mysql', 'sqlite', 'mongodb', 'redis'],
    'comms':      ['email', 'send message', 'calendar', 'contacts', 'slack',
                   'teams', 'sms', 'notification', 'send email', 'discord'],
}

DESCRIPTION_LENGTH_THRESHOLDS = {
    'short_suspicious': 20,
    'normal_max': 500,
    'elevated_scrutiny': 1000,
}


# ---------------------------------------------------------------------------
# Core Scanning Functions
# ---------------------------------------------------------------------------

def scan_injection_patterns(text: str, context: str) -> list[dict]:
    """RT-CHECK-01/03: Scan for injection trigger phrases."""
    findings = []

    # Critical patterns
    for pattern, label in INJECTION_CRITICAL_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append({
                'severity': 'CRITICAL',
                'type': 'injection_critical',
                'pattern': label,
                'evidence': text[max(0, match.start() - 30):match.end() + 30].strip(),
                'context': context,
            })

    # High patterns (count; flag if 2+)
    high_matches = []
    for pattern, label in INJECTION_HIGH_PATTERNS:
        if pattern.search(text):
            high_matches.append(label)

    if len(high_matches) >= 2:
        findings.append({
            'severity': 'HIGH',
            'type': 'injection_high',
            'pattern': f"Multiple high signals: {', '.join(high_matches)}",
            'evidence': f"{len(high_matches)} high-risk patterns detected",
            'context': context,
        })

    return findings


def scan_unicode_anomalies(text: str) -> dict:
    """RT-CHECK-02: Detect Unicode anomalies."""
    result = {
        'has_non_ascii': False,
        'zero_width_chars': [],
        'direction_overrides': [],
        'homoglyphs': [],
    }

    # Check for non-ASCII
    if len(text) != len(text.encode('ascii', 'ignore').decode()):
        result['has_non_ascii'] = True

    # Check zero-width characters
    for char in text:
        if char in ZERO_WIDTH_CHARS:
            result['zero_width_chars'].append(f"U+{ord(char):04X} ({unicodedata.name(char, 'UNKNOWN')})")
        if char in DIRECTION_OVERRIDE_CHARS:
            result['direction_overrides'].append(f"U+{ord(char):04X} ({unicodedata.name(char, 'UNKNOWN')})")
        if char in CYRILLIC_HOMOGLYPH_MAP:
            result['homoglyphs'].append(f"'{char}' (U+{ord(char):04X}) looks like '{CYRILLIC_HOMOGLYPH_MAP[char]}'")

    return result


def scan_credentials(text: str) -> list[dict]:
    """RT-CHECK-04: Detect credentials and suspicious URLs."""
    findings = []

    for pattern, cred_type, severity in CREDENTIAL_PATTERNS:
        match = pattern.search(text)
        if match:
            # Redact the actual value in evidence
            raw = match.group(0)
            redacted = raw[:6] + '***REDACTED***' if len(raw) > 6 else '***REDACTED***'
            findings.append({
                'type': 'credential_exposure',
                'credential_type': cred_type,
                'severity': severity,
                'evidence': redacted,
            })

    # Suspicious URLs
    url_match = SUSPICIOUS_URL_PATTERN.search(text)
    if url_match:
        findings.append({
            'type': 'suspicious_url',
            'severity': 'HIGH',
            'credential_type': 'Suspicious External URL',
            'evidence': url_match.group(0),
        })

    return findings


def assess_capabilities(description: str) -> list[str]:
    """RT-CHECK-05: Identify declared capabilities from description keywords."""
    desc_lower = description.lower()
    detected = []
    for capability, keywords in CAPABILITY_KEYWORDS.items():
        if any(kw in desc_lower for kw in keywords):
            detected.append(capability)
    return detected


def check_description_length(description: str) -> Optional[dict]:
    """RT-CHECK-01: Check description length thresholds."""
    length = len(description)
    if length < DESCRIPTION_LENGTH_THRESHOLDS['short_suspicious']:
        return {'severity': 'LOW', 'length': length, 'category': 'suspiciously_short'}
    if length > DESCRIPTION_LENGTH_THRESHOLDS['elevated_scrutiny']:
        return {'severity': 'HIGH', 'length': length, 'category': 'elevated_scrutiny'}
    if length > DESCRIPTION_LENGTH_THRESHOLDS['normal_max']:
        return {'severity': 'MEDIUM', 'length': length, 'category': 'above_normal'}
    return None


# ---------------------------------------------------------------------------
# Main Scanner
# ---------------------------------------------------------------------------

class RuntimeScanner:
    def __init__(self, manifest: dict):
        self.tools: list[dict] = manifest.get('tools', [])
        self.findings: list[dict] = []
        self.finding_counter = 0
        self.scan_timestamp = datetime.now(timezone.utc).isoformat()

    def _next_id(self) -> str:
        self.finding_counter += 1
        return f"MCP-RT-{self.finding_counter:03d}"

    def _add_finding(self, check: str, tool_name: str, server: str,
                     severity: str, vuln_type: str, vulnerability_id: str,
                     adversa_rank: Optional[int], owasp_mcp: str,
                     evidence: str, recommendation: str) -> None:
        self.findings.append({
            'finding_id': self._next_id(),
            'check': check,
            'tool_name': tool_name,
            'server': server,
            'severity': severity,
            'type': vuln_type,
            'vulnerability_id': vulnerability_id,
            'adversa_rank': adversa_rank,
            'owasp_mcp': owasp_mcp,
            'evidence': evidence,
            'recommendation': recommendation,
        })

    def run(self) -> dict:
        """Execute all 6 RT-CHECKs and return structured results."""
        servers_seen: set[str] = set()
        tool_names_by_server: dict[str, list[str]] = defaultdict(list)
        all_tool_names: dict[str, list[str]] = defaultdict(list)  # name → servers

        for tool in self.tools:
            name = tool.get('name', '<unnamed>')
            server = tool.get('server', '<unknown>')
            description = tool.get('description', '')
            schema = tool.get('inputSchema', {})

            servers_seen.add(server)
            tool_names_by_server[server].append(name)
            all_tool_names[name].append(server)

            # RT-CHECK-01: Description Poisoning
            self._check_description_poisoning(name, server, description)

            # RT-CHECK-02: Tool Name Integrity
            self._check_name_integrity(name, server)

            # RT-CHECK-03: Schema Poisoning
            self._check_schema_poisoning(name, server, schema)

            # RT-CHECK-04: Credential & URL Exposure
            # Scan all text fields
            all_text = f"{name} {description} {json.dumps(schema)}"
            self._check_credentials(name, server, all_text)

            # RT-CHECK-05: Permission Assessment
            self._check_permissions(name, server, description)

        # RT-CHECK-06: Server Count & Shadow Risk
        self._check_shadow_servers(servers_seen, all_tool_names, tool_names_by_server)

        return self._build_result(servers_seen, tool_names_by_server)

    def _check_description_poisoning(self, name: str, server: str, description: str) -> None:
        """RT-CHECK-01"""
        # Length check
        length_result = check_description_length(description)
        if length_result and length_result['category'] in ('elevated_scrutiny', 'suspiciously_short'):
            self._add_finding(
                check='RT-CHECK-01',
                tool_name=name, server=server,
                severity=length_result['severity'],
                vuln_type='description_length_anomaly',
                vulnerability_id='V03',
                adversa_rank=3, owasp_mcp='MCP03',
                evidence=f"Description length: {length_result['length']} chars "
                         f"({length_result['category']})",
                recommendation=(
                    'Review tool description content. Unusually long descriptions '
                    'often hide injected instructions. Verify with the server operator.'
                ),
            )

        # Injection patterns
        injection_findings = scan_injection_patterns(description, f'description of tool {name!r}')
        for f in injection_findings:
            self._add_finding(
                check='RT-CHECK-01',
                tool_name=name, server=server,
                severity=f['severity'],
                vuln_type='tool_poisoning_description',
                vulnerability_id='V03',
                adversa_rank=3, owasp_mcp='MCP03',
                evidence=f"Pattern detected: {f['pattern']!r} — Evidence: {f['evidence']!r}",
                recommendation=(
                    f'Immediate action required: tool description contains injection-trigger language. '
                    f'Disconnect server {server!r} and review its source code before reconnecting.'
                ),
            )

        # Unicode anomalies in description
        unicode_result = scan_unicode_anomalies(description)
        if unicode_result['zero_width_chars'] or unicode_result['direction_overrides']:
            chars = unicode_result['zero_width_chars'] + unicode_result['direction_overrides']
            self._add_finding(
                check='RT-CHECK-01',
                tool_name=name, server=server,
                severity='HIGH',
                vuln_type='unicode_anomaly_description',
                vulnerability_id='V03',
                adversa_rank=3, owasp_mcp='MCP03',
                evidence=f"Unicode anomalies in description: {chars}",
                recommendation=(
                    'Zero-width or direction-override characters detected in tool description. '
                    'This is a known technique to hide injected instructions from human reviewers. '
                    'Do not trust this tool; contact the server operator.'
                ),
            )

    def _check_name_integrity(self, name: str, server: str) -> None:
        """RT-CHECK-02"""
        unicode_result = scan_unicode_anomalies(name)

        if unicode_result['homoglyphs']:
            self._add_finding(
                check='RT-CHECK-02',
                tool_name=name, server=server,
                severity='HIGH',
                vuln_type='tool_name_spoofing',
                vulnerability_id='V12',
                adversa_rank=12, owasp_mcp='MCP03',
                evidence=f"Homoglyph characters in tool name: {unicode_result['homoglyphs']}",
                recommendation=(
                    f'Tool name {name!r} contains Cyrillic characters that visually resemble '
                    f'Latin characters. This is a known Tool Name Spoofing technique (V12). '
                    f'Verify with the server operator; do not invoke this tool.'
                ),
            )

        if unicode_result['zero_width_chars'] or unicode_result['direction_overrides']:
            chars = unicode_result['zero_width_chars'] + unicode_result['direction_overrides']
            self._add_finding(
                check='RT-CHECK-02',
                tool_name=name, server=server,
                severity='HIGH',
                vuln_type='tool_name_unicode',
                vulnerability_id='V12',
                adversa_rank=12, owasp_mcp='MCP03',
                evidence=f"Invisible Unicode characters in tool name: {chars}",
                recommendation=(
                    'Tool name contains invisible Unicode characters. '
                    'This can be used for spoofing or evasion. Investigate this server.'
                ),
            )

    def _check_schema_poisoning(self, name: str, server: str, schema: dict) -> None:
        """RT-CHECK-03"""
        properties = schema.get('properties', {})
        required_fields = schema.get('required', [])

        # Check for write/execute tool with no required fields
        write_execute_indicators = ['write', 'create', 'update', 'delete', 'remove',
                                    'execute', 'run', 'send', 'post', 'put', 'patch',
                                    'insert', 'modify', 'edit', 'publish', 'deploy']
        is_write_tool = any(ind in name.lower() for ind in write_execute_indicators)
        if is_write_tool and not required_fields:
            self._add_finding(
                check='RT-CHECK-03',
                tool_name=name, server=server,
                severity='MEDIUM',
                vuln_type='schema_no_required_fields',
                vulnerability_id='V11',
                adversa_rank=11, owasp_mcp='MCP03',
                evidence=f"Write/execute tool with no 'required' fields in schema",
                recommendation=(
                    'Write and execute tools should declare required fields in their schema. '
                    'This ensures parameters are validated before execution. '
                    'Add a "required" array to the inputSchema.'
                ),
            )

        # Check each parameter description for injection
        for param_name, param_def in properties.items():
            param_desc = param_def.get('description', '')
            if param_desc:
                injection_findings = scan_injection_patterns(
                    param_desc, f'parameter {param_name!r} of tool {name!r}'
                )
                for f in injection_findings:
                    self._add_finding(
                        check='RT-CHECK-03',
                        tool_name=name, server=server,
                        severity=f['severity'],
                        vuln_type='schema_parameter_poisoning',
                        vulnerability_id='V11',
                        adversa_rank=11, owasp_mcp='MCP03',
                        evidence=f"Parameter {param_name!r}: {f['evidence']!r}",
                        recommendation=(
                            f'Parameter description in {name!r} contains injection-trigger language. '
                            f'This is Full Schema Poisoning (V11). Disconnect server {server!r}.'
                        ),
                    )

            # Check for overly permissive types
            param_type = param_def.get('type', '')
            if param_type == 'any' or (param_type == '' and not param_def.get('$ref')):
                self._add_finding(
                    check='RT-CHECK-03',
                    tool_name=name, server=server,
                    severity='MEDIUM',
                    vuln_type='schema_permissive_type',
                    vulnerability_id='V11',
                    adversa_rank=11, owasp_mcp='MCP03',
                    evidence=f"Parameter {param_name!r} has no type constraint",
                    recommendation=(
                        f'Parameter {param_name!r} should have an explicit type and '
                        f'validation constraints (maxLength, pattern, enum) to prevent injection.'
                    ),
                )

    def _check_credentials(self, name: str, server: str, all_text: str) -> None:
        """RT-CHECK-04"""
        cred_findings = scan_credentials(all_text)
        for cf in cred_findings:
            self._add_finding(
                check='RT-CHECK-04',
                tool_name=name, server=server,
                severity=cf['severity'],
                vuln_type=cf['type'],
                vulnerability_id='V08',
                adversa_rank=8, owasp_mcp='MCP01',
                evidence=f"{cf['credential_type']}: {cf['evidence']}",
                recommendation=(
                    f'Possible credential exposure detected in tool definition for {name!r}. '
                    f'Remove credentials from tool definitions immediately. '
                    f'Use environment variables or secrets managers.'
                ),
            )

    def _check_permissions(self, name: str, server: str, description: str) -> None:
        """RT-CHECK-05"""
        capabilities = assess_capabilities(description)
        if capabilities:
            # Check for mismatch: tool purpose vs capabilities
            name_lower = name.lower()
            benign_purpose_keywords = [
                'calculator', 'math', 'compute', 'weather', 'forecast',
                'translate', 'convert', 'format', 'prettify', 'lint',
                'search', 'lookup', 'find',
            ]
            high_risk_caps = {'shell_exec', 'filesystem', 'network', 'comms'}

            is_benign_purpose = any(kw in name_lower for kw in benign_purpose_keywords)
            has_high_risk_caps = bool(set(capabilities) & high_risk_caps)

            if is_benign_purpose and has_high_risk_caps:
                self._add_finding(
                    check='RT-CHECK-05',
                    tool_name=name, server=server,
                    severity='HIGH',
                    vuln_type='overbroad_permissions',
                    vulnerability_id='V19',
                    adversa_rank=19, owasp_mcp='MCP02',
                    evidence=(
                        f"Tool purpose appears benign ('{name}') but description claims "
                        f"high-risk capabilities: {capabilities}"
                    ),
                    recommendation=(
                        f'Tool {name!r} claims capabilities ({capabilities}) that are '
                        f'inconsistent with its apparent purpose. This is a strong indicator '
                        f'of Overbroad Permissions (V19) or Tool Poisoning (V03). '
                        f'Review this tool carefully before use.'
                    ),
                )

    def _check_shadow_servers(
        self,
        servers_seen: set[str],
        all_tool_names: dict[str, list[str]],
        tool_names_by_server: dict[str, list[str]],
    ) -> None:
        """RT-CHECK-06"""
        # Server count
        if len(servers_seen) > 5:
            self._add_finding(
                check='RT-CHECK-06',
                tool_name='<all tools>',
                server='<multiple>',
                severity='MEDIUM',
                vuln_type='high_server_count',
                vulnerability_id='V27',
                adversa_rank=None, owasp_mcp='MCP09',
                evidence=f"{len(servers_seen)} MCP servers connected: {sorted(servers_seen)}",
                recommendation=(
                    'More than 5 MCP servers are connected simultaneously. This increases '
                    'attack surface and tool interference risk (V30). Review whether all '
                    'servers are necessary and consider disconnecting unused ones.'
                ),
            )

        # Tool shadowing
        for tool_name, servers in all_tool_names.items():
            if len(servers) > 1:
                self._add_finding(
                    check='RT-CHECK-06',
                    tool_name=tool_name,
                    server=' vs '.join(servers),
                    severity='HIGH',
                    vuln_type='tool_shadowing',
                    vulnerability_id='V17',
                    adversa_rank=17, owasp_mcp='MCP03',
                    evidence=(
                        f"Tool named {tool_name!r} exists on {len(servers)} servers: {servers}. "
                        f"The agent may invoke the wrong one."
                    ),
                    recommendation=(
                        f'Tool Shadowing (V17) detected: {tool_name!r} is defined on multiple servers. '
                        f'Implement namespace prefixing (e.g., "server1__tool_name") or ensure only '
                        f'one server defines each tool name.'
                    ),
                )

    def _build_result(self, servers_seen: set[str],
                      tool_names_by_server: dict[str, list[str]]) -> dict:
        severity_counts: dict[str, int] = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            sev = f.get('severity', 'INFO')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        clean_tools = len(self.tools) - len({f['tool_name'] for f in self.findings
                                              if f['tool_name'] != '<all tools>'})
        clean_tools = max(0, clean_tools)

        return {
            'scan_mode': 'runtime_introspection',
            'scan_timestamp': self.scan_timestamp,
            'servers_found': sorted(servers_seen),
            'tools_scanned': len(self.tools),
            'findings': self.findings,
            'summary': {
                'total_findings': len(self.findings),
                'critical': severity_counts['CRITICAL'],
                'high': severity_counts['HIGH'],
                'medium': severity_counts['MEDIUM'],
                'low': severity_counts['LOW'],
                'clean_tools': clean_tools,
                'poisoned_tools': len({f['tool_name'] for f in self.findings
                                       if f.get('type') in ('tool_poisoning_description',
                                                             'schema_parameter_poisoning')}),
                'shadowed_names': [f['tool_name'] for f in self.findings
                                   if f.get('type') == 'tool_shadowing'],
                'unicode_anomalies': [f['tool_name'] for f in self.findings
                                      if 'unicode' in f.get('type', '')],
                'credential_exposures': [f['tool_name'] for f in self.findings
                                         if f.get('type') == 'credential_exposure'],
            },
        }


# ---------------------------------------------------------------------------
# Report Formatting
# ---------------------------------------------------------------------------

def format_markdown_report(result: dict) -> str:
    """Format scan results as a Markdown Runtime Tool Manifest Security Summary."""
    summary = result['summary']
    findings = result['findings']
    servers = result['servers_found']
    tool_count = result['tools_scanned']
    ts = result['scan_timestamp']

    # Determine overall status
    if summary['critical'] > 0:
        status_icon = '🚨'
        status_text = 'CRITICAL ISSUES FOUND'
    elif summary['high'] > 0:
        status_icon = '⚠️'
        status_text = 'WARNINGS FOUND'
    else:
        status_icon = '✅'
        status_text = 'CLEAN'

    lines = [
        '# 🔍 Runtime Tool Manifest Security Scan',
        '',
        f'**Scan Time:** {ts}',
        f'**Mode:** Automatic Runtime Introspection (Mode 1)',
        f'**Scope:** All MCP tools currently connected to this agent',
        '',
        '---',
        '',
        '## Connected Servers & Tools Inventory',
        '',
        '| Server | Tools |',
        '|--------|-------|',
    ]

    for server in servers:
        lines.append(f'| {server} | (see manifest) |')

    lines += [
        '',
        f'**Total:** {tool_count} tools across {len(servers)} servers',
        '',
        '---',
        '',
        '## Scan Results',
        '',
        f'### {status_icon} Overall Status: {status_text}',
        '',
    ]

    if not findings:
        lines += [
            '✅ **All Clear**',
            '',
            f'No poisoning indicators, Unicode anomalies, credential exposure, '
            f'tool shadowing, or suspicious patterns detected. All {tool_count} tools '
            f'from {len(servers)} connected MCP server(s) passed runtime inspection.',
        ]
    else:
        # Group by severity
        for severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
            sev_findings = [f for f in findings if f.get('severity') == severity]
            if not sev_findings:
                continue
            icon = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '📋', 'LOW': 'ℹ️', 'INFO': 'ℹ️'}[severity]
            lines.append(f'### {icon} {severity} Findings')
            lines.append('')
            for f in sev_findings:
                lines += [
                    f'**[{f["finding_id"]}] {f["type"].replace("_", " ").title()}**',
                    '',
                    f'| Field | Value |',
                    f'|-------|-------|',
                    f'| Tool | `{f["tool_name"]}` |',
                    f'| Server | `{f["server"]}` |',
                    f'| Check | {f["check"]} |',
                    f'| Vulnerability | {f["vulnerability_id"]} |',
                    f'| OWASP MCP | {f["owasp_mcp"]} |',
                    '' if not f.get('adversa_rank') else f'| Adversa Rank | #{f["adversa_rank"]} |',
                    '',
                    f'**Evidence:** {f["evidence"]}',
                    '',
                    f'**Recommendation:** {f["recommendation"]}',
                    '',
                    '---',
                    '',
                ]

    lines += [
        '## Checks Performed',
        '',
        '| Check | Status |',
        '|-------|--------|',
    ]

    checks = ['RT-CHECK-01', 'RT-CHECK-02', 'RT-CHECK-03', 'RT-CHECK-04', 'RT-CHECK-05', 'RT-CHECK-06']
    check_names = {
        'RT-CHECK-01': 'Tool Description Poisoning',
        'RT-CHECK-02': 'Tool Name Integrity & Unicode',
        'RT-CHECK-03': 'Schema & Parameter Poisoning',
        'RT-CHECK-04': 'Credential & External URL Exposure',
        'RT-CHECK-05': 'Permission & Capability Assessment',
        'RT-CHECK-06': 'Server Count & Shadow Risk',
    }
    for check in checks:
        has_findings = any(f['check'] == check for f in findings)
        icon = '⚠️' if has_findings else '✅'
        lines.append(f'| {check}: {check_names[check]} | {icon} |')

    lines += [
        '',
        '---',
        '',
        '*This scan was performed automatically. To perform a deeper review of any server\'s '
        'source code or configuration, share that material for a full audit (Mode 2).*',
    ]

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def load_manifest(args: argparse.Namespace) -> dict:
    """Load manifest from file or stdin."""
    if args.stdin:
        raw = sys.stdin.read()
    elif args.manifest:
        path = Path(args.manifest)
        if not path.exists():
            print(f"Error: file not found: {args.manifest}", file=sys.stderr)
            sys.exit(1)
        raw = path.read_text(encoding='utf-8')
    else:
        print("Error: provide --manifest FILE or --stdin", file=sys.stderr)
        sys.exit(1)

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description='MCP Runtime Tool Manifest Security Scanner (Mode 1)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--manifest', metavar='FILE', help='Path to JSON tool manifest file')
    parser.add_argument('--stdin', action='store_true', help='Read JSON manifest from stdin')
    parser.add_argument('--output', metavar='FILE', help='Write Markdown report to file (default: stdout)')
    parser.add_argument('--json', action='store_true', help='Output raw JSON instead of Markdown')
    parser.add_argument('--fail-on', choices=['critical', 'high', 'medium', 'low'],
                        default=None, help='Exit with code 1 if findings of this severity or higher exist')
    args = parser.parse_args()

    manifest = load_manifest(args)
    scanner = RuntimeScanner(manifest)
    result = scanner.run()

    if args.json:
        output = json.dumps(result, indent=2)
    else:
        output = format_markdown_report(result)

    if args.output:
        Path(args.output).write_text(output, encoding='utf-8')
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Exit code for CI/CD integration
    if args.fail_on:
        severity_order = ['critical', 'high', 'medium', 'low']
        threshold_idx = severity_order.index(args.fail_on)
        summary = result['summary']
        for sev in severity_order[:threshold_idx + 1]:
            if summary.get(sev, 0) > 0:
                sys.exit(1)


if __name__ == '__main__':
    main()
