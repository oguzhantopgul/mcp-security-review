# MCP Security Review Skill

A Claude Code Agent Skill that equips Claude with deep, structured expertise to perform **comprehensive security reviews of MCP (Model Context Protocol) servers and deployments**.

Built on four authoritative security frameworks:
- **OWASP GenAI Cheat Sheet** v1.0 (Oct 2025) — consumer-side guidance
- **OWASP GenAI Dev Guide** v1.0 (Feb 2026) — developer-side guidance + 5-point Security Minimum Bar
- **Adversa AI Top 25 MCP Vulnerabilities** (Sep 2025) — ranked vulnerability taxonomy (V01–V30)
- **OWASP MCP Top 10** v0.1 (2025) — top 10 risk categories (MCP01–MCP10)

---

## How It Works

The skill operates in **two complementary modes** that run together:

### Mode 1 — Runtime Introspection (automatic)

Every time the skill activates, it **immediately scans all currently-connected MCP tools** in the agent's live context — before asking the user for anything. It inspects tool names, descriptions, schemas, and parameter definitions for:

| Check | What It Detects |
|-------|----------------|
| RT-CHECK-01 | Tool description poisoning — injection phrases, long descriptions, hidden instructions |
| RT-CHECK-02 | Tool name integrity — homoglyphs, Unicode spoofing, typosquatting |
| RT-CHECK-03 | Schema/parameter poisoning — injected instructions in parameter descriptions |
| RT-CHECK-04 | Credential & secret exposure — API keys, tokens, suspicious external URLs |
| RT-CHECK-05 | Permission/capability over-claiming — tool purpose vs. declared capabilities |
| RT-CHECK-06 | Server count & tool shadowing — duplicate tool names across servers |

### Mode 2 — User-Provided Input Review (on demand)

Reviews any MCP server the user provides:
- **Source code** → full static analysis (10 code-level checks)
- **Config file** (mcp.json, claude_desktop_config.json) → config security review (6 checks)
- **GitHub URL** → repository fetch and analysis
- **Architecture description** → threat model assessment

Every finding is mapped to all four frameworks and includes: severity, evidence, framework references, and a specific actionable recommendation.

---

## File Structure

```
mcp-security-review/
├── SKILL.md                              ← Main skill entry point
├── references/
│   ├── vulnerability-taxonomy.md         ← V01–V30 master mapping table with detailed entries
│   ├── owasp-mcp-top10.md                ← MCP01–MCP10 detailed write-ups
│   ├── security-controls.md              ← Controls library (C01–C25) with code examples
│   ├── report-templates.md               ← Templates A (Full Audit), B (Quick), C (Runtime)
│   └── runtime-scan-patterns.md          ← All regex patterns and detection constants
├── scripts/
│   ├── introspect_runtime.py             ← CLI runtime manifest scanner (Mode 1)
│   ├── analyze_code.py                   ← Static code analyzer (Mode 2)
│   ├── check_config.py                   ← Config file analyzer (Mode 2)
│   └── generate_report.py               ← Report generator (Templates A & B)
├── assets/
│   └── severity-matrix.md               ← CVSS + Adversa severity scoring criteria
├── References/                           ← Source PDFs (authoritative references)
└── MCP_SECURITY_REVIEW_SKILL.md          ← Full project specification
```

---

## Vulnerability Coverage

The skill covers **30 vulnerability classes** (V01–V30) spanning the full Adversa AI Top 25 plus additional OWASP categories:

| Severity | Count | Key Vulnerabilities |
|----------|-------|---------------------|
| Critical | 4 | Prompt Injection (V01), Command Injection (V02), Tool Poisoning (V03), RCE (V04) |
| Critical | 2 | Unauthenticated Access (V05), Confused Deputy/OAuth (V06) |
| High | 9 | Config Poisoning (V07), Credential Theft (V08), Token Passthrough (V09), Path Traversal (V10), Schema Poisoning (V11), Tool Name Spoofing (V12), NeighborJack (V13), Rug Pull (V14), Resource Content Poisoning (V18) |
| Medium | 8 | ATPA (V15), Session Flaws (V16), Tool Shadowing (V17), Overbroad Permissions (V19), Cross-Repo Theft (V20), SQL Injection (V21), Insufficient Audit (V26), Supply Chain (V28) |
| Medium/Low | 7 | Context Bleeding (V22), Config Exposure (V23), Preference Manipulation (V24), Cross-Tenant Exposure (V25), Shadow MCPs (V27), Memory Poisoning (V29), Tool Interference (V30) |

---

## Using the Scripts

The scripts can be used standalone in CI/CD pipelines or by Claude during analysis.

### Runtime Manifest Scanner

```bash
# Scan a JSON dump of your tool manifest
python scripts/introspect_runtime.py --manifest tools.json
python scripts/introspect_runtime.py --manifest tools.json --output report.md
python scripts/introspect_runtime.py --stdin < tools.json

# CI/CD: fail build if high-severity findings exist
python scripts/introspect_runtime.py --manifest tools.json --fail-on high
```

**Input format** (`tools.json`):
```json
{
  "tools": [
    {
      "name": "read_file",
      "description": "Reads a file from the filesystem",
      "server": "filesystem-mcp",
      "inputSchema": {
        "type": "object",
        "properties": {
          "path": { "type": "string", "description": "File path to read" }
        },
        "required": ["path"]
      }
    }
  ]
}
```

### Static Code Analyzer

```bash
# Analyze a single file
python scripts/analyze_code.py --path server.py

# Analyze a directory
python scripts/analyze_code.py --path ./src/ --output findings.json

# CI/CD: fail on critical or high findings
python scripts/analyze_code.py --path ./src/ --fail-on high
```

### Config File Analyzer

```bash
# Analyze MCP config
python scripts/check_config.py --config mcp.json
python scripts/check_config.py --config claude_desktop_config.json --output findings.json

# YAML configs also supported (requires PyYAML)
python scripts/check_config.py --config config.yaml
```

### Report Generator

```bash
# Full audit report from static findings
python scripts/generate_report.py \
  --findings findings.json \
  --template full \
  --target "My MCP Server" \
  --deployment "Local STDIO" \
  --output report.md

# Quick assessment
python scripts/generate_report.py --findings findings.json --template quick

# Combine runtime + static findings
python scripts/generate_report.py \
  --findings runtime.json \
  --findings2 static.json \
  --template full \
  --output combined-report.md
```

---

## CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  mcp-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Analyze MCP server source
        run: |
          python scripts/analyze_code.py \
            --path src/ \
            --output findings-code.json \
            --fail-on high

      - name: Analyze MCP config
        run: |
          python scripts/check_config.py \
            --config mcp.json \
            --output findings-config.json \
            --fail-on high

      - name: Generate security report
        run: |
          python scripts/generate_report.py \
            --findings findings-code.json \
            --findings2 findings-config.json \
            --template full \
            --output security-report.md

      - name: Upload report artifact
        uses: actions/upload-artifact@v4
        with:
          name: mcp-security-report
          path: security-report.md
```

---

## Report Output

Every review produces a structured report with:

1. **Executive Summary** — overall risk rating and plain-language summary
2. **Security Minimum Bar** — 5-item OWASP GenAI Dev Guide checklist (PASS/FAIL/PARTIAL)
3. **Runtime Manifest Findings** (MCP-RT-NNN) — from Mode 1 automatic scan
4. **Static Code/Config Findings** (MCP-FIND-NNN) — from Mode 2 user-provided review
5. **Framework Coverage Summary** — how many items were checked across all 4 frameworks
6. **Prioritized Remediation Roadmap** — Immediate / 1 week / 1 month / 3 months

### Example Finding

```
### [MCP-FIND-001] 🚨 No authentication mechanism found in any analyzed file

| Field | Value |
|-------|-------|
| Severity | CRITICAL |
| Adversa AI Rank | #5 — Unauthenticated Access |
| OWASP MCP Top 10 | MCP07 — Weak Authentication |
| Dev Guide Section | §5 Auth & Authorization |
| Vulnerability ID | V05 |

**Evidence:** (no oauth/jwt/bearer/auth_required/verify_token patterns detected)

**Recommendation:** Implement OAuth 2.1 with PKCE for all MCP endpoints. Validate all
token claims (iss, aud, exp) on every request. See references/security-controls.md
for C01 implementation example.
```

---

## Security Controls Library

`references/security-controls.md` contains 25 security controls (C01–C25) with full implementation examples covering:

- **Authentication**: OAuth 2.1, PKCE, token claim validation, mTLS
- **Input validation**: allowlisting, parameterized queries, safe subprocess
- **Tool integrity**: version pinning, hash verification, cryptographic manifests
- **Session isolation**: per-session state, lifecycle cleanup, resource quotas
- **Deployment**: container hardening, network binding, secrets management
- **Governance**: MCP registry, approval workflow, audit logging, HITL gates
- **Scanning tools**: mcp-scan, semgrep, mcp-watch, Trail of Bits context-protector

---

## Escalation Alerts

The skill will immediately alert with prominent warnings for:

| Trigger | Alert Level | Example |
|---------|-------------|---------|
| Injection phrases in tool descriptions | 🚨 CRITICAL | `ignore all previous instructions` found |
| Unicode direction overrides in tool names | ⚠️ HIGH | RTL override character detected |
| API credentials in tool definitions | ⚠️ HIGH | `sk-abc123...` pattern in description |
| Tool name collision across servers | ⚠️ HIGH | `send_email` defined on 2 servers |
| External tunneling URLs in definitions | ⚠️ HIGH | `ngrok.io` URL in tool description |
| No authentication found in codebase | 🚨 CRITICAL | No oauth/jwt/bearer patterns found |

---

## Requirements

- **Python 3.9+** (scripts)
- **PyYAML** (optional, for YAML config files): `pip install pyyaml`
- No external API calls — all analysis is static and local

---

## References

| Document | Version | Purpose |
|----------|---------|---------|
| OWASP GenAI Cheat Sheet — Securely Using Third-Party MCP Servers | v1.0, Oct 2025 | Consumer-side guidance |
| OWASP GenAI Dev Guide — Secure MCP Server Development | v1.0, Feb 2026 | Developer-side guidance |
| Adversa AI Top 25 MCP Vulnerabilities | Sep 2025 | Vulnerability taxonomy |
| OWASP MCP Top 10 | v0.1, 2025 | OWASP risk categories |

Source PDFs are in the `References/` directory.
