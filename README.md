# MCP Security Review — Claude Code Agent Skill

A Claude Code Agent Skill for security reviews of MCP (Model Context Protocol) servers. Claude reads the material directly — source code, tool definitions, config files — and reasons about it adversarially. No scripts, no regex, no static analysis pipeline.

## How It Works

One unified review protocol, applied to whatever input is available:

1. **Identify inputs** — live tool manifest, source code, GitHub URL, config file, or architecture description
2. **Establish context** — deployment model, trust context, external reach (determines severity)
3. **Map the surface** — enumerate files, identify entry points, high-risk modules, and dependency files
4. **Read adversarially** — for every function crossing a trust boundary, ask: what does this trust? what can it reach? what breaks with adversarial input? where is auth? what is the blast radius?
5. **Check by input type** — specific checks for tool definitions, source code, config files, and dependency files
6. **Apply vulnerability checklist** — assess V01-V30 against the actual material
7. **Report** — structured findings with evidence, framework mappings, and a Security Minimum Bar assessment

**Why no scripts?** Regex catches known patterns. Claude catches logic flaws: auth that runs after the operation, a trust assumption that shouldn't be there, a data flow that reaches a sink without validation. These require reading and reasoning, not pattern matching.

## What It Can Review

| Input | How to Provide |
|-------|---------------|
| Your connected MCP tools | Ask "scan your tools" or "are your MCPs safe?" |
| Source code | Paste or attach files, or provide a local directory path |
| GitHub repository | Provide the GitHub URL |
| Config file | Paste or provide the file path |
| Architecture / description | Describe the server in natural language |

Any combination works. If multiple inputs are provided, all are reviewed and findings are merged.

## Security Frameworks

All findings are mapped to three OWASP frameworks and the skill's own vulnerability taxonomy:

| Framework | What It Covers |
|-----------|---------------|
| MCP Security Vulnerability Taxonomy | V01-V30, severity scores, detection signals, secure code patterns |
| OWASP MCP Top 10 | MCP-specific risk categories MCP01-MCP10 (2025) |
| OWASP GenAI Dev Guide | Developer-side implementation guidance §1-§8 (Feb 2026) |
| OWASP GenAI Cheat Sheet | Consumer-side guidance for third-party MCP servers (Oct 2025) |

## File Structure

```
SKILL.md                           ← Skill entry point (install this)
References/
  vulnerability-taxonomy.md        ← V01-V30 master mapping with descriptions and mitigations
  security-controls.md             ← Controls library with implementation examples
  report-templates.md              ← Template A (Full Audit), B (Quick Assessment), C (Manifest)
```

## Installation

```bash
# Create a directory for the skill and its reference files
mkdir -p ~/.claude/skills/mcp-security-review
cp SKILL.md ~/.claude/skills/mcp-security-review/
cp -r References/ ~/.claude/skills/mcp-security-review/
```

The skill file and its `References/` directory must be installed together. SKILL.md instructs the agent to read files from `References/` during every review — without them, the skill cannot produce consistent output.

## Usage

**Review connected MCP tools:**
```
/mcp-security-review
```
or: *"scan your tools"*, *"are your MCPs safe?"*, *"what tools do you have connected?"*

**Review a GitHub repository:**
```
/mcp-security-review https://github.com/org/mcp-server
```

**Review a config file:**
```
/mcp-security-review ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**Review pasted code or a description:**
Ask *"review this MCP server"* and paste the content.

## Report Output

| Template | When Used | Contents |
|----------|-----------|---------|
| Template A — Full Audit | Source code or GitHub URL reviewed | Executive summary, Security Minimum Bar, all findings with evidence, what was not assessed |
| Template B — Quick Assessment | Config-only or description-only | Key risk areas, Security Minimum Bar, key recommendations |
| Template C — Manifest Summary | Tool manifest only | Per-tool findings table, clean/alert status |

Every report ends with the **Security Minimum Bar** (5-point OWASP checklist).

## Vulnerability Coverage

| ID | Vulnerability | Severity | OWASP MCP |
|----|--------------|----------|-----------|
| V01 | Prompt Injection | Critical | MCP06, MCP10 |
| V02 | Command Injection | Critical | MCP05 |
| V03 | Tool Poisoning | Critical | MCP03 |
| V05 | Unauthenticated Access | Critical | MCP07 |
| V08 | Credential and Token Exposure | High | MCP01 |
| V13 | Network Binding Misconfiguration | High | MCP09 |
| V14 | Rug Pull / Unpinned Dependencies | High | MCP04 |
| V17 | Tool Shadowing | Medium | MCP03 |
| V19 | Overbroad Permissions | Medium | MCP02 |
| V25 | Cross-Tenant State Leakage | Medium | MCP10 |

Full V01-V30 taxonomy: `References/vulnerability-taxonomy.md`.

## Requirements

- Claude Code with skill support
- Git (optional, for GitHub URL reviews)
- No Python, no dependencies, no external tools
