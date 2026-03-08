#!/usr/bin/env python3
"""
MCP Static Code Analyzer — Mode 2

Performs security analysis on MCP server source code files, checking for
10 categories of vulnerabilities mapped to the Adversa AI Top 25 and OWASP MCP Top 10.

Usage:
    python analyze_code.py --path server.py
    python analyze_code.py --path ./src/
    python analyze_code.py --path server.py --output findings.json
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Supported File Types
# ---------------------------------------------------------------------------

SUPPORTED_EXTENSIONS = {'.py', '.js', '.ts', '.mjs', '.cjs'}
DEPENDENCY_FILES = {'requirements.txt', 'pyproject.toml', 'package.json',
                    'Pipfile', 'setup.cfg', 'poetry.lock'}

# ---------------------------------------------------------------------------
# Detection Patterns
# ---------------------------------------------------------------------------

# Check 1: Command Injection
CMD_INJECTION_PATTERNS = [
    (re.compile(r'\bsubprocess\b'), 'subprocess import/usage'),
    (re.compile(r'\bos\.system\s*\('), 'os.system()'),
    (re.compile(r'\bos\.popen\s*\('), 'os.popen()'),
    (re.compile(r'\bos\.exec[lv]p?\s*\('), 'os.execl/v/p()'),
    (re.compile(r'\beval\s*\('), 'eval()'),
    (re.compile(r'\bexec\s*\('), 'exec()'),
    (re.compile(r'shell\s*=\s*True'), 'shell=True'),
    (re.compile(r'\bchild_process\b'), 'child_process (Node.js)'),
    (re.compile(r'\bexecSync\s*\('), 'execSync() (Node.js)'),
    (re.compile(r'\bspawnSync\s*\('), 'spawnSync() (Node.js)'),
    (re.compile(r'\bexecFile\s*\('), 'execFile() (Node.js)'),
]

# Check 2: Hardcoded Secrets
HARDCODED_SECRET_PATTERNS = [
    (re.compile(r'\b(api_key|apikey|API_KEY|APIKEY)\s*=\s*["\'][^"\']{8,}["\']'), 'hardcoded api_key'),
    (re.compile(r'\b(secret|SECRET)\s*=\s*["\'][^"\']{8,}["\']'), 'hardcoded secret'),
    (re.compile(r'\b(password|PASSWORD|passwd|PASSWD)\s*=\s*["\'][^"\']{4,}["\']'), 'hardcoded password'),
    (re.compile(r'\b(token|TOKEN)\s*=\s*["\'][^"\']{8,}["\']'), 'hardcoded token'),
    (re.compile(r'\b(bearer|BEARER)\s*=\s*["\'][^"\']{8,}["\']'), 'hardcoded bearer'),
    (re.compile(r'["\']sk-[A-Za-z0-9]{32,}["\']'), 'OpenAI key literal'),
    (re.compile(r'["\']ghp_[A-Za-z0-9]{36}["\']'), 'GitHub PAT literal'),
    (re.compile(r'["\']AKIA[0-9A-Z]{16}["\']'), 'AWS key literal'),
    (re.compile(r'Authorization\s*:\s*["\']Bearer\s+[A-Za-z0-9]{16,}'), 'hardcoded Authorization header'),
]

# Check 3: Network Binding
BINDING_PATTERNS = [
    (re.compile(r'["\']0\.0\.0\.0["\']'), '0.0.0.0 binding'),
    (re.compile(r'host\s*=\s*["\']0\.0\.0\.0["\']'), 'host="0.0.0.0"'),
    (re.compile(r'listen\s*\(\s*\d+\s*,\s*["\']0\.0\.0\.0["\']'), 'listen(port, "0.0.0.0")'),
]

# Check 4: Authentication indicators
AUTH_INDICATORS = [
    re.compile(r'\boauth\b', re.I),
    re.compile(r'\bjwt\b', re.I),
    re.compile(r'\bbearer\b', re.I),
    re.compile(r'\bauth_required\b', re.I),
    re.compile(r'@authenticate', re.I),
    re.compile(r'\bverify_token\b', re.I),
    re.compile(r'\bapi_key_required\b', re.I),
    re.compile(r'\brequire_auth\b', re.I),
    re.compile(r'\bAuthorizat', re.I),
    re.compile(r'\bBasicAuth\b', re.I),
]

# Check 5: Logging of secrets
CREDENTIAL_VAR_PATTERNS = [
    re.compile(r'\b(api_key|token|secret|password|credential|bearer)\b', re.I),
]
LOG_CALL_PATTERNS = [
    re.compile(r'\blogging\.(debug|info|warning|error|critical)\b'),
    re.compile(r'\bprint\s*\('),
    re.compile(r'\bconsole\.(log|debug|info|error)\b'),
    re.compile(r'\blogger\.(debug|info|warning|error|critical)\b'),
]

# Check 6: SQL Injection
SQL_INJECTION_PATTERNS = [
    (re.compile(r'f["\'].*\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*\{'), 'f-string SQL'),
    (re.compile(r'["\'].*%s.*["\'].*%.*\b(SELECT|INSERT|UPDATE|DELETE)\b', re.I), '%-format SQL'),
    (re.compile(r'\.format\s*\(.*\).*["\'].*\b(SELECT|INSERT|UPDATE|DELETE)\b', re.I), '.format() SQL'),
    (re.compile(r'\bexecute\s*\(\s*["\'].*\+', re.I), 'string concat in execute()'),
]

# Check 7: Path Traversal
PATH_TRAVERSAL_PATTERNS = [
    (re.compile(r'\bopen\s*\(.*[a-zA-Z_]\w*\b(?!.*resolve)(?!.*abspath)'), 'open() with variable path'),
    (re.compile(r'\bPath\s*\(.*[a-zA-Z_]\w*\b(?!.*resolve)'), 'Path() with variable'),
    (re.compile(r'\bfs\.readFile\s*\(.*[a-zA-Z_]\w*'), 'fs.readFile() with variable'),
    (re.compile(r'\bfs\.writeFile\s*\(.*[a-zA-Z_]\w*'), 'fs.writeFile() with variable'),
]

# Check 8: Token Passthrough
TOKEN_PASSTHROUGH_PATTERNS = [
    (re.compile(r'headers\s*=\s*\{[^}]*["\']Authorization["\'][^}]*request\.(headers|args)'),
     'forwarding request Authorization header'),
    (re.compile(r'token\s*=\s*request\.(headers|args|json|form)'), 'extracting token from request'),
]

# Check 9: Shared/Global State
SHARED_STATE_PATTERNS = [
    (re.compile(r'^(?:user_|session_|cache_)?(?:data|state|context|store)\s*=\s*(?:\{\}|\[\])',
                re.MULTILINE), 'module-level mutable dict/list (user data risk)'),
    (re.compile(r'^[A-Z_]{3,}\s*=\s*\{\}', re.MULTILINE), 'module-level CONSTANT dict'),
]

# Check 10: Dependency pinning
UNPINNED_PIP_PATTERN = re.compile(r'^(?!#)([a-zA-Z0-9_\-]+)\s*(?:>=|<=|>|<|\^|~|!=|$)', re.MULTILINE)
PINNED_PIP_PATTERN = re.compile(r'^(?!#)([a-zA-Z0-9_\-]+)\s*==', re.MULTILINE)
UNPINNED_NPM_PATTERN = re.compile(r'"[^"]+"\s*:\s*"\s*[\^~]')


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class CodeFinding:
    check: str
    file: str
    line: int
    severity: str
    description: str
    snippet: str
    vulnerability_id: str
    adversa_rank: Optional[int]
    owasp_mcp: str
    dev_guide_section: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Analysis Engine
# ---------------------------------------------------------------------------

class CodeAnalyzer:
    def __init__(self):
        self.findings: list[CodeFinding] = []
        self.auth_found = False
        self.all_lines: list[tuple[str, int, str]] = []  # (file, lineno, line_text)

    def analyze_path(self, target: Path) -> None:
        """Analyze a file or directory recursively."""
        if target.is_file():
            self._analyze_file(target)
        elif target.is_dir():
            for ext in SUPPORTED_EXTENSIONS:
                for f in target.rglob(f'*{ext}'):
                    self._analyze_file(f)
            for dep_file in DEPENDENCY_FILES:
                dep_path = target / dep_file
                if dep_path.exists():
                    self._analyze_dependencies(dep_path)
        else:
            print(f"Warning: {target} is not a file or directory", file=sys.stderr)

    def _analyze_file(self, filepath: Path) -> None:
        """Analyze a single source file."""
        try:
            content = filepath.read_text(encoding='utf-8', errors='replace')
        except OSError as e:
            print(f"Warning: cannot read {filepath}: {e}", file=sys.stderr)
            return

        lines = content.splitlines()
        file_str = str(filepath)

        # Track all lines for cross-line checks
        for i, line in enumerate(lines, 1):
            self.all_lines.append((file_str, i, line))

        self._check_command_injection(file_str, lines)
        self._check_hardcoded_secrets(file_str, lines)
        self._check_network_binding(file_str, lines)
        self._check_auth_presence(content)
        self._check_secret_logging(file_str, lines)
        self._check_sql_injection(file_str, lines)
        self._check_path_traversal(file_str, lines)
        self._check_token_passthrough(file_str, lines)
        self._check_shared_state(file_str, lines)

    def _add(self, check: str, file: str, line: int, severity: str,
              description: str, snippet: str, vuln_id: str,
              adversa: Optional[int], owasp: str, dev_guide: str,
              recommendation: str) -> None:
        self.findings.append(CodeFinding(
            check=check, file=file, line=line, severity=severity,
            description=description, snippet=snippet.strip()[:200],
            vulnerability_id=vuln_id, adversa_rank=adversa,
            owasp_mcp=owasp, dev_guide_section=dev_guide,
            recommendation=recommendation,
        ))

    def _check_command_injection(self, file: str, lines: list[str]) -> None:
        for i, line in enumerate(lines, 1):
            for pattern, label in CMD_INJECTION_PATTERNS:
                if pattern.search(line):
                    # shell=True with subprocess is most critical
                    severity = 'CRITICAL' if 'shell=True' in line or 'eval' in line or 'exec' in line else 'HIGH'
                    self._add(
                        check='command_injection',
                        file=file, line=i, severity=severity,
                        description=f'Potential command injection: {label}',
                        snippet=line,
                        vuln_id='V02', adversa=2, owasp='MCP05',
                        dev_guide='§3 Data Validation',
                        recommendation=(
                            'Replace shell execution with safe alternatives: use list-form subprocess '
                            'calls (never shell=True with dynamic input), strict input allowlists, '
                            'and run the process with minimal OS permissions.'
                        ),
                    )
                    break  # one finding per line per check

    def _check_hardcoded_secrets(self, file: str, lines: list[str]) -> None:
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            for pattern, label in HARDCODED_SECRET_PATTERNS:
                if pattern.search(line):
                    self._add(
                        check='hardcoded_secrets',
                        file=file, line=i, severity='HIGH',
                        description=f'Possible hardcoded secret: {label}',
                        snippet='[REDACTED — see file]',
                        vuln_id='V08', adversa=8, owasp='MCP01',
                        dev_guide='§6 Secure Deployment',
                        recommendation=(
                            'Remove hardcoded secrets. Load credentials from environment variables '
                            'injected by a secrets manager (HashiCorp Vault, AWS Secrets Manager). '
                            'Rotate the exposed credential immediately.'
                        ),
                    )
                    break

    def _check_network_binding(self, file: str, lines: list[str]) -> None:
        for i, line in enumerate(lines, 1):
            for pattern, label in BINDING_PATTERNS:
                if pattern.search(line):
                    self._add(
                        check='network_binding',
                        file=file, line=i, severity='HIGH',
                        description=f'Server binds to all interfaces: {label} (NeighborJack risk)',
                        snippet=line,
                        vuln_id='V13', adversa=13, owasp='MCP09',
                        dev_guide='§1 Architecture',
                        recommendation=(
                            'Bind to 127.0.0.1 for local-only servers. If internet-facing, '
                            'ensure TLS 1.2+ and strong authentication are in place. '
                            'Never expose an unauthenticated server on 0.0.0.0.'
                        ),
                    )
                    break

    def _check_auth_presence(self, content: str) -> None:
        """Check 4: Update global flag if auth is found in content."""
        if any(p.search(content) for p in AUTH_INDICATORS):
            self.auth_found = True

    def _check_secret_logging(self, file: str, lines: list[str]) -> None:
        """Check 5: Flag logging calls within 5 lines of credential variable usage."""
        for i, line in enumerate(lines, 1):
            if any(p.search(line) for p in CREDENTIAL_VAR_PATTERNS):
                # Check surrounding 5 lines for log calls
                window_start = max(0, i - 3)
                window_end = min(len(lines), i + 3)
                window = lines[window_start:window_end]
                for wline in window:
                    if any(p.search(wline) for p in LOG_CALL_PATTERNS):
                        self._add(
                            check='credential_logging',
                            file=file, line=i, severity='HIGH',
                            description='Credential variable used near logging call — possible credential leakage',
                            snippet=line,
                            vuln_id='V08', adversa=8, owasp='MCP01',
                            dev_guide='§6 Secure Deployment',
                            recommendation=(
                                'Add a log redaction filter to strip credential patterns from log output. '
                                'Never log raw token or secret values. Use structured logging with '
                                'explicit field allowlisting.'
                            ),
                        )
                        break

    def _check_sql_injection(self, file: str, lines: list[str]) -> None:
        for i, line in enumerate(lines, 1):
            for pattern, label in SQL_INJECTION_PATTERNS:
                if pattern.search(line):
                    self._add(
                        check='sql_injection',
                        file=file, line=i, severity='MEDIUM',
                        description=f'Possible SQL injection: {label}',
                        snippet=line,
                        vuln_id='V21', adversa=21, owasp='MCP05',
                        dev_guide='§3 Data Validation',
                        recommendation=(
                            'Use parameterized queries or an ORM for all database operations. '
                            'Never build SQL strings using f-strings, % formatting, or .format() '
                            'with user-controlled values.'
                        ),
                    )
                    break

    def _check_path_traversal(self, file: str, lines: list[str]) -> None:
        for i, line in enumerate(lines, 1):
            for pattern, label in PATH_TRAVERSAL_PATTERNS:
                if pattern.search(line):
                    # Only flag if .resolve() or os.path.abspath is NOT on the same line
                    if 'resolve()' not in line and 'abspath' not in line:
                        self._add(
                            check='path_traversal',
                            file=file, line=i, severity='HIGH',
                            description=f'Possible path traversal: {label} without path normalization',
                            snippet=line,
                            vuln_id='V10', adversa=10, owasp='MCP05',
                            dev_guide='§3 Data Validation',
                            recommendation=(
                                'Normalize all user-provided file paths using Path.resolve() '
                                'and verify the resolved path is within the expected base directory '
                                'using Path.is_relative_to(base_dir). Never pass raw user input to '
                                'file open operations.'
                            ),
                        )
                        break

    def _check_token_passthrough(self, file: str, lines: list[str]) -> None:
        for i, line in enumerate(lines, 1):
            for pattern, label in TOKEN_PASSTHROUGH_PATTERNS:
                if pattern.search(line):
                    self._add(
                        check='token_passthrough',
                        file=file, line=i, severity='HIGH',
                        description=f'Possible token passthrough: {label}',
                        snippet=line,
                        vuln_id='V09', adversa=9, owasp='MCP07',
                        dev_guide='§5 Auth & Authorization',
                        recommendation=(
                            'Validate token claims (iss, aud, exp, scope) before forwarding to '
                            'downstream services. Use per-user token binding; do not forward '
                            'the raw incoming token to third-party APIs without validation.'
                        ),
                    )
                    break

    def _check_shared_state(self, file: str, lines: list[str]) -> None:
        content = '\n'.join(lines)
        for pattern, label in SHARED_STATE_PATTERNS:
            for match in pattern.finditer(content):
                lineno = content[:match.start()].count('\n') + 1
                self._add(
                    check='shared_state',
                    file=file, line=lineno, severity='MEDIUM',
                    description=f'Module-level mutable variable may cause cross-user data leakage: {label}',
                    snippet=match.group(0).strip(),
                    vuln_id='V25', adversa=25, owasp='MCP10',
                    dev_guide='§1 Architecture',
                    recommendation=(
                        'Use per-request or per-session state. Move any user-specific data into '
                        'a session-scoped context object. Never store user data in module-level '
                        'or class-level mutable variables in multi-tenant deployments.'
                    ),
                )

    def _analyze_dependencies(self, dep_path: Path) -> None:
        """Check 10: Dependency version pinning."""
        try:
            content = dep_path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            return

        file_str = str(dep_path)
        name = dep_path.name

        if name == 'requirements.txt':
            self._check_pip_pinning(file_str, content)
        elif name == 'package.json':
            self._check_npm_pinning(file_str, content)
        elif name == 'pyproject.toml':
            self._check_pyproject_pinning(file_str, content)

    def _check_pip_pinning(self, file: str, content: str) -> None:
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('-'):
                continue
            # If line has a package name but uses >= <= > < ^ ~ or no version at all
            if UNPINNED_PIP_PATTERN.match(stripped) and '==' not in stripped:
                pkg_name = stripped.split('[')[0].split('>=')[0].split('<=')[0].split('>')[0]\
                               .split('<')[0].split('~')[0].split('^')[0].strip()
                self._add(
                    check='dependency_pinning',
                    file=file, line=i, severity='MEDIUM',
                    description=f'Unpinned dependency: {pkg_name!r} — Rug Pull risk',
                    snippet=stripped,
                    vuln_id='V14', adversa=14, owasp='MCP04',
                    dev_guide='§7 Governance',
                    recommendation=(
                        f'Pin {pkg_name!r} to an exact version using ==. Generate a locked '
                        f'requirements file with hashes: pip-compile --generate-hashes. '
                        f'Install with: pip install --require-hashes -r requirements.txt'
                    ),
                )

    def _check_npm_pinning(self, file: str, content: str) -> None:
        try:
            pkg = json.loads(content)
        except json.JSONDecodeError:
            return

        for dep_section in ('dependencies', 'devDependencies'):
            deps = pkg.get(dep_section, {})
            for i, (pkg_name, version) in enumerate(deps.items(), 1):
                if version.startswith(('^', '~', '>', '<', '*')):
                    self._add(
                        check='dependency_pinning',
                        file=file, line=i, severity='MEDIUM',
                        description=f'Unpinned npm dependency: {pkg_name!r}@{version!r} — Rug Pull risk',
                        snippet=f'"{pkg_name}": "{version}"',
                        vuln_id='V14', adversa=14, owasp='MCP04',
                        dev_guide='§7 Governance',
                        recommendation=(
                            f'Pin {pkg_name!r} to an exact version. Commit package-lock.json '
                            f'and use "npm ci" (not "npm install") in production/CI environments.'
                        ),
                    )

    def _check_pyproject_pinning(self, file: str, content: str) -> None:
        # Simple check for ^, ~, >=, <= in pyproject.toml dependency strings
        pattern = re.compile(r'"([a-zA-Z0-9_\-]+)\s*([\^~>=<]+)\s*([0-9][^"]*)"')
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            m = pattern.search(line)
            if m and '==' not in m.group(2):
                self._add(
                    check='dependency_pinning',
                    file=file, line=i, severity='MEDIUM',
                    description=f'Unpinned dependency in pyproject.toml: {m.group(1)!r}',
                    snippet=line.strip(),
                    vuln_id='V14', adversa=14, owasp='MCP04',
                    dev_guide='§7 Governance',
                    recommendation=(
                        f'Pin {m.group(1)!r} to an exact version in pyproject.toml. '
                        f'Use poetry.lock or pip-compile to lock the full dependency tree.'
                    ),
                )

    def finalize(self) -> dict:
        """Add auth absence finding and build result dict."""
        if not self.auth_found and self.findings:
            # Only flag if we actually analyzed some code
            self.findings.insert(0, CodeFinding(
                check='authentication_absence',
                file='<entire codebase>',
                line=0,
                severity='CRITICAL',
                description='No authentication mechanism found in any analyzed file',
                snippet='(no oauth/jwt/bearer/auth_required/verify_token patterns detected)',
                vulnerability_id='V05',
                adversa_rank=5,
                owasp_mcp='MCP07',
                dev_guide_section='§5 Auth & Authorization',
                recommendation=(
                    'Implement OAuth 2.1 with PKCE for all MCP endpoints. Validate all token '
                    'claims (iss, aud, exp) on every request. See references/security-controls.md '
                    'for C01 implementation example.'
                ),
            ))

        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        self.findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return {
            'scan_mode': 'static_code_analysis',
            'findings': [f.to_dict() for f in self.findings],
            'summary': {
                'total': len(self.findings),
                'critical': counts['CRITICAL'],
                'high': counts['HIGH'],
                'medium': counts['MEDIUM'],
                'low': counts['LOW'],
                'auth_found': self.auth_found,
            },
        }


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description='MCP Static Code Security Analyzer (Mode 2)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--path', required=True, metavar='PATH',
                        help='Source file or directory to analyze')
    parser.add_argument('--output', metavar='FILE',
                        help='Write JSON findings to file (default: stdout)')
    parser.add_argument('--fail-on', choices=['critical', 'high', 'medium', 'low'],
                        default=None, help='Exit with code 1 if findings at this severity or higher exist')
    args = parser.parse_args()

    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Error: path not found: {args.path}", file=sys.stderr)
        sys.exit(2)
    # Optional: uncomment to restrict analysis to within the current working directory
    # base = Path.cwd()
    # if not str(target).startswith(str(base)):
    #     print(f"Error: path '{target}' is outside the working directory", file=sys.stderr)
    #     sys.exit(2)

    analyzer = CodeAnalyzer()
    analyzer.analyze_path(target)
    result = analyzer.finalize()

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
