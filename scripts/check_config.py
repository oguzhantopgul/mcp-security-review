#!/usr/bin/env python3
"""
MCP Config File Analyzer — Mode 2

Analyzes MCP configuration files (JSON/YAML) for security misconfigurations,
credential exposure, insecure URLs, and policy issues.

Supported config formats:
  - claude_desktop_config.json
  - mcp.json / .mcp/config.json
  - Any MCP server config in JSON or YAML

Usage:
    python check_config.py --config mcp.json
    python check_config.py --config claude_desktop_config.json --output findings.json
    python check_config.py --config config.yaml
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Credential Detection Patterns
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'sk-[A-Za-z0-9]{32,}'), 'OpenAI API Key'),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), 'GitHub PAT'),
    (re.compile(r'ghs_[A-Za-z0-9]{36}'), 'GitHub Server Token'),
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'AWS Access Key'),
    (re.compile(r'xox[baprs]-[0-9]{10,}-[A-Za-z0-9-]+'), 'Slack Token'),
    (re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*'), 'Bearer Token'),
    (re.compile(r'https?://[^:\s/]+:[^@\s/]+@'), 'URL with Embedded Credentials'),
    (re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'), 'Possible Base64 Secret'),
]

SENSITIVE_KEY_NAMES: set[str] = {
    'api_key', 'apikey', 'api-key', 'secret', 'password', 'passwd',
    'token', 'bearer', 'auth_token', 'access_token', 'refresh_token',
    'private_key', 'client_secret', 'app_secret', 'webhook_secret',
    'authorization', 'credential', 'credentials',
}

INSECURE_URL_PATTERN = re.compile(r'^http://', re.I)  # non-HTTPS (non-localhost)
LOCALHOST_PATTERN = re.compile(r'^http://(localhost|127\.0\.0\.1)', re.I)
BINDING_0000_PATTERN = re.compile(r'0\.0\.0\.0')
WILDCARD_SCOPE_PATTERN = re.compile(r'[\*]')
VERSION_PATTERN = re.compile(r'^\d+\.\d+\.\d+$')  # exact semver


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class ConfigFinding:
    check: str
    severity: str
    config_path: str
    json_path: str
    description: str
    evidence: str
    vulnerability_id: str
    adversa_rank: Optional[int]
    owasp_mcp: str
    dev_guide_section: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Config Analyzer
# ---------------------------------------------------------------------------

class ConfigAnalyzer:
    def __init__(self, config_path: str, config_data: dict):
        self.config_path = config_path
        self.config = config_data
        self.findings: list[ConfigFinding] = []

    def _add(self, check: str, severity: str, json_path: str, description: str,
             evidence: str, vuln_id: str, adversa: Optional[int], owasp: str,
             dev_guide: str, recommendation: str) -> None:
        self.findings.append(ConfigFinding(
            check=check, severity=severity, config_path=self.config_path,
            json_path=json_path, description=description,
            evidence=evidence[:300], vulnerability_id=vuln_id,
            adversa_rank=adversa, owasp_mcp=owasp, dev_guide_section=dev_guide,
            recommendation=recommendation,
        ))

    def analyze(self) -> list[ConfigFinding]:
        """Run all 6 config checks."""
        self._walk_config(self.config, '')
        self._check_auto_discovery()
        return self.findings

    def _walk_config(self, node: Any, path: str) -> None:
        """Recursively walk the config tree, running checks on each value."""
        if isinstance(node, dict):
            for key, value in node.items():
                child_path = f"{path}.{key}" if path else key
                self._check_credential_in_value(key, value, child_path)
                self._check_server_url(key, value, child_path)
                self._check_localhost_binding(key, value, child_path)
                self._check_version_pinning(key, value, child_path)
                self._check_excessive_permissions(key, value, child_path)
                self._walk_config(value, child_path)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                self._walk_config(item, f"{path}[{i}]")
        elif isinstance(node, str):
            # Scan string values for embedded credentials
            self._scan_string_for_credentials(node, path)

    def _check_credential_in_value(self, key: str, value: Any, path: str) -> None:
        """Check 1: Credential in config values."""
        key_lower = key.lower().replace('-', '_')

        if key_lower in SENSITIVE_KEY_NAMES and isinstance(value, str) and len(value) > 3:
            # Key name suggests this is a credential
            if not value.startswith('${') and not value.startswith('%'):
                # Not an environment variable reference
                self._add(
                    check='credential_in_config',
                    severity='HIGH',
                    json_path=path,
                    description=f'Sensitive key {key!r} contains a literal value (not env var reference)',
                    evidence=f'{key}: [REDACTED — {len(value)} chars]',
                    vuln_id='V08', adversa=8, owasp='MCP01',
                    dev_guide='§6 Secure Deployment',
                    recommendation=(
                        f'Replace the literal value of {key!r} with an environment variable '
                        f'reference (e.g., ${{MY_SECRET}}) and inject the value at runtime '
                        f'via a secrets manager. Never commit credentials in config files.'
                    ),
                )

    def _scan_string_for_credentials(self, value: str, path: str) -> None:
        """Scan any string value for credential patterns."""
        for pattern, cred_type in CREDENTIAL_PATTERNS:
            if pattern.search(value):
                self._add(
                    check='credential_pattern_in_value',
                    severity='HIGH',
                    json_path=path,
                    description=f'Credential pattern detected in config value: {cred_type}',
                    evidence=f'{cred_type} pattern at path {path!r} [value redacted]',
                    vuln_id='V08', adversa=8, owasp='MCP01',
                    dev_guide='§6 Secure Deployment',
                    recommendation=(
                        'Remove this credential from the config file. Rotate it immediately. '
                        'Use environment variable references or a secrets manager.'
                    ),
                )
                break  # one finding per path per scan

    def _check_server_url(self, key: str, value: Any, path: str) -> None:
        """Check 2: Non-HTTPS server URLs."""
        url_keys = {'url', 'endpoint', 'host', 'server', 'base_url', 'api_url'}
        key_lower = key.lower().replace('-', '_')

        if key_lower in url_keys and isinstance(value, str):
            if INSECURE_URL_PATTERN.match(value) and not LOCALHOST_PATTERN.match(value):
                self._add(
                    check='insecure_url',
                    severity='HIGH',
                    json_path=path,
                    description='MCP server URL uses HTTP instead of HTTPS (non-localhost)',
                    evidence=f'{key}: {value!r}',
                    vuln_id='V08', adversa=8, owasp='MCP01',
                    dev_guide='§6 Secure Deployment',
                    recommendation=(
                        f'Change {value!r} to HTTPS. All non-localhost MCP server URLs must '
                        f'use HTTPS (TLS 1.2+) to protect credentials and data in transit.'
                    ),
                )

    def _check_localhost_binding(self, key: str, value: Any, path: str) -> None:
        """Check 3: 0.0.0.0 binding in config."""
        if isinstance(value, str) and BINDING_0000_PATTERN.search(value):
            self._add(
                check='localhost_binding',
                severity='HIGH',
                json_path=path,
                description='Server configured to bind to all interfaces (0.0.0.0) — NeighborJack risk',
                evidence=f'{key}: {value!r}',
                vuln_id='V13', adversa=13, owasp='MCP09',
                dev_guide='§1 Architecture',
                recommendation=(
                    'Change 0.0.0.0 to 127.0.0.1 for local-only servers. If network-accessible '
                    'binding is required, ensure TLS and authentication are enforced.'
                ),
            )

    def _check_version_pinning(self, key: str, value: Any, path: str) -> None:
        """Check 4: Version pinning for server definitions."""
        version_keys = {'version', 'tag', 'ref', 'image'}
        key_lower = key.lower()

        if key_lower in version_keys and isinstance(value, str):
            # Flag if version is 'latest', 'main', 'master', or uses ^ ~ ranges
            if value in ('latest', 'main', 'master', 'HEAD', '*') or \
               value.startswith(('^', '~', '>=', '>')):
                self._add(
                    check='version_pinning',
                    severity='MEDIUM',
                    json_path=path,
                    description=f'MCP server version not pinned: {value!r} — Rug Pull risk',
                    evidence=f'{key}: {value!r}',
                    vuln_id='V14', adversa=14, owasp='MCP04',
                    dev_guide='§7 Governance',
                    recommendation=(
                        f'Pin to a specific version (e.g., "1.2.3" or a full git SHA). '
                        f'Avoid "latest", "main", or version ranges which allow silent updates '
                        f'that could introduce malicious changes (Rug Pull, V14).'
                    ),
                )

    def _check_excessive_permissions(self, key: str, value: Any, path: str) -> None:
        """Check 5: Wildcard or admin-level permission scopes."""
        scope_keys = {'scope', 'scopes', 'permissions', 'access', 'grants'}
        key_lower = key.lower()

        if key_lower in scope_keys:
            scope_str = json.dumps(value) if not isinstance(value, str) else value
            if WILDCARD_SCOPE_PATTERN.search(scope_str):
                self._add(
                    check='excessive_permissions',
                    severity='HIGH',
                    json_path=path,
                    description='Wildcard (*) scope or permissions detected — Overbroad Permissions',
                    evidence=f'{key}: {scope_str[:100]!r}',
                    vuln_id='V19', adversa=19, owasp='MCP02',
                    dev_guide='§5 Auth & Authorization',
                    recommendation=(
                        'Replace wildcard scopes with the minimum specific scopes needed for each tool. '
                        'Apply least-privilege: if a tool only needs read:files, do not grant write:files or *.'
                    ),
                )

            admin_signals = ['admin', 'write:org', 'repo:*', 'delete', 'all:access', 'superuser']
            if any(sig in scope_str.lower() for sig in admin_signals):
                self._add(
                    check='excessive_permissions',
                    severity='HIGH',
                    json_path=path,
                    description='Admin or elevated permission scope detected',
                    evidence=f'{key}: {scope_str[:100]!r}',
                    vuln_id='V19', adversa=19, owasp='MCP02',
                    dev_guide='§5 Auth & Authorization',
                    recommendation=(
                        'Review whether admin-level permissions are truly required. '
                        'Apply least-privilege principles and request only the minimum needed scope.'
                    ),
                )

    def _check_auto_discovery(self) -> None:
        """Check 6: Auto-discovery without allowlist."""
        config_str = json.dumps(self.config).lower()
        auto_discovery_signals = [
            'auto_discover', 'autodiscover', 'auto-discover',
            'discover_servers', 'dynamic_servers', 'allow_all_servers',
            'server_discovery',
        ]
        for signal in auto_discovery_signals:
            if signal in config_str:
                self._add(
                    check='auto_discovery',
                    severity='HIGH',
                    json_path='<config root>',
                    description=f'Auto-discovery feature detected ({signal!r}) without visible allowlist',
                    evidence=f'Config contains: {signal!r}',
                    vuln_id='V27', adversa=None, owasp='MCP09',
                    dev_guide='§7 Governance',
                    recommendation=(
                        'Disable auto-discovery or restrict it to an explicit server allowlist with '
                        'integrity verification (hash/signature check). Unrestricted auto-discovery '
                        'allows rogue MCP servers to be injected into the agent environment.'
                    ),
                )
                break

    def build_result(self) -> dict:
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        self.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        return {
            'scan_mode': 'config_analysis',
            'config_file': self.config_path,
            'findings': [f.to_dict() for f in self.findings],
            'summary': {
                'total': len(self.findings),
                'critical': severity_counts['CRITICAL'],
                'high': severity_counts['HIGH'],
                'medium': severity_counts['MEDIUM'],
                'low': severity_counts['LOW'],
            },
        }


# ---------------------------------------------------------------------------
# Config Loader
# ---------------------------------------------------------------------------

def load_config(path: Path) -> dict:
    """Load JSON or YAML config file."""
    try:
        content = path.read_text(encoding='utf-8')
    except OSError as e:
        print(f"Error: cannot read {path}: {e}", file=sys.stderr)
        sys.exit(1)

    ext = path.suffix.lower()

    if ext in ('.yaml', '.yml'):
        try:
            import yaml
            return yaml.safe_load(content) or {}
        except ImportError:
            print("Warning: PyYAML not installed. Install it with: pip install pyyaml", file=sys.stderr)
            print("Attempting to parse as JSON...", file=sys.stderr)
        except Exception as e:
            print(f"Error parsing YAML: {e}", file=sys.stderr)
            sys.exit(1)

    # Default: JSON
    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in {path}: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description='MCP Configuration File Security Analyzer (Mode 2)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--config', required=True, metavar='FILE',
                        help='Path to MCP config file (JSON or YAML)')
    parser.add_argument('--output', metavar='FILE',
                        help='Write JSON findings to file (default: stdout)')
    parser.add_argument('--fail-on', choices=['critical', 'high', 'medium', 'low'],
                        default=None, help='Exit with code 1 if findings at this severity or higher exist')
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: config file not found: {args.config}", file=sys.stderr)
        sys.exit(2)

    config_data = load_config(config_path)
    analyzer = ConfigAnalyzer(str(config_path), config_data)
    analyzer.analyze()
    result = analyzer.build_result()

    output = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding='utf-8')
        print(f"Findings written to {args.output}", file=sys.stderr)
    else:
        print(output)

    if args.fail_on:
        severity_order = ['critical', 'high', 'medium', 'low']
        threshold_idx = severity_order.index(args.fail_on)
        summary = result['summary']
        for sev in severity_order[:threshold_idx + 1]:
            if summary.get(sev, 0) > 0:
                sys.exit(1)


if __name__ == '__main__':
    main()
