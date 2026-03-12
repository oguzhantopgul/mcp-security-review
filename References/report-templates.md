# MCP Security Report Templates

Three templates for different review contexts. Use Template A for full audits (source code or GitHub URL), Template B for quick assessments (config or description only), Template C for tool manifest inspection.

---

## Template A: Full Security Audit Report

*For source code or GitHub URL reviews.*

```markdown
# MCP Security Audit Report

**Target:** [MCP Server Name / Description]
**Review Date:** [YYYY-MM-DD]
**Reviewer:** Claude (MCP Security Review Skill)
**Input Type:** [Source Code / GitHub URL / Config File / Description]
**Deployment Context:** [Local STDIO / Remote HTTP / Multi-tenant / Enterprise]

---

## Executive Summary

**Overall Risk Rating:** [CRITICAL / HIGH / MEDIUM / LOW]
**Total Findings:** [N] ([X] Critical, [X] High, [X] Medium, [X] Low, [X] Informational)
**Security Minimum Bar:** [PASS / FAIL] — [N]/5 checklist items passed

[2-3 sentence plain-language summary of the biggest risks and recommended priority actions.
Written for a non-technical stakeholder. Example: "This MCP server has a critical authentication
gap that allows any network-reachable client to invoke all tools without credentials. Combined
with a command injection vulnerability in the script execution tool, this could allow full
server compromise. Immediate action is required before this server can be safely deployed."]

---

## Security Minimum Bar (OWASP GenAI Dev Guide)

| # | Control Area | Status | Notes |
|---|-------------|--------|-------|
| 1 | Strong Identity, Auth & Policy Enforcement | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 2 | Strict Isolation & Lifecycle Control | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 3 | Trusted, Controlled Tooling | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 4 | Schema-Driven Validation Everywhere | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 5 | Hardened Deployment & Continuous Oversight | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |

---

## Findings

*Sorted by severity: Critical → High → Medium → Low → Informational*

### [MCP-001] [Finding Title]

| Field | Value |
|-------|-------|
| Severity | [CRITICAL / HIGH / MEDIUM / LOW / INFO] |
| Source | [Tool Manifest / Source Code / Config / Architecture] |
| Affected Component | [Server / Client / Config / Tool Manifest] |
| Vulnerability ID | [VNN — Vulnerability Name] |
| OWASP MCP | [MCPNN — Category Name] |
| Dev Guide Section | [§N Section Name] |
| Effort to Fix | [Hours / Days / Weeks / Architecture Change] |

**Description:**
[What is wrong and why it matters in 2-4 sentences.]

**Evidence:**
```[language]
[Exact quote from code, config, or tool definition — with file:line reference]
```

**Recommendation:**
[Specific, actionable fix. Include example secure code where applicable.]

---

[Repeat MCP-NNN for each finding]

---

## Framework Coverage

| Framework | Items Checked | Findings Mapped |
|-----------|--------------|-----------------|
| MCP Security Vulnerability Taxonomy | V01-V30 | [N] |
| OWASP MCP Top 10 | 10 | [N] |
| OWASP GenAI Dev Guide | 8 domains | [N] |
| OWASP GenAI Cheat Sheet | 6 areas | [N] |

---

## What Was Not Assessed

[List areas that could not be reviewed due to missing input, and what would enable that review.]
- **[Area]** — [what is needed to assess it]
```

---

## Template B: Quick Risk Assessment

*For config-only or description-only reviews — a concise threat model.*

```markdown
# MCP Quick Risk Assessment

**Target:** [MCP Server Name / Description]
**Date:** [YYYY-MM-DD]
**Input:** [Description only / Config only / Partial information]

---

## Preliminary Risk Rating: [CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN]

*Note: This assessment is based on [description/config/partial info] only.
A definitive risk rating requires source code review.*

---

## Key Risk Areas

### [HIGH/MEDIUM/LOW] Risk: [Risk Name]

**Concern:** [What could go wrong based on known patterns for this type of server]
**Likelihood:** [High/Medium/Low given the stated deployment context]
**Framework Reference:** [VNN, OWASP MCPNN]

---

[Repeat for each identified risk area]

---

## Consumer-Side Checklist (OWASP GenAI Cheat Sheet)

Before using this MCP server:
- [ ] **Verify source** — Is this from a trusted, known publisher?
- [ ] **Check version pinning** — Is the version pinned and hash-verified?
- [ ] **Review tool descriptions** — Have definitions been scanned for injection patterns?
- [ ] **Assess token scopes** — Are OAuth scopes limited to what is actually needed?
- [ ] **Establish governance** — Is this server in your approved MCP registry?
- [ ] **Plan for revocation** — Can you quickly disconnect if a rug pull is detected?

---

## Security Minimum Bar (OWASP GenAI Dev Guide)

*Assessed from [description/config] only — most items require source code review to confirm.*

| # | Control Area | Status | Notes |
|---|-------------|--------|-------|
| 1 | Strong Identity, Auth & Policy Enforcement | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 2 | Strict Isolation & Lifecycle Control | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 3 | Trusted, Controlled Tooling | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 4 | Schema-Driven Validation Everywhere | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 5 | Hardened Deployment & Continuous Oversight | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |

---

*For a definitive assessment, share source code or a GitHub link to enable a Full Audit (Template A).*
```

---

## Template C: Tool Manifest Security Summary

*For tool manifest inspection — produced when the user asks to scan connected MCP tools.*

```markdown
# MCP Tool Manifest Security Review

**Review Date:** [YYYY-MM-DD]
**Scope:** All MCP tools currently connected to this agent

---

## Connected Servers

| Server | Tool Count | Capabilities Declared |
|--------|------------|----------------------|
| [server-name] | [N] tools | [filesystem / shell / network / database / comms] |

**Total:** [N] tools across [M] servers

---

## Result: [ALL CLEAR / WARNINGS FOUND / CRITICAL ISSUES FOUND]

---

[IF CLEAN:]

No poisoning indicators, Unicode anomalies, credential exposure, tool shadowing,
or suspicious patterns detected across all [N] tools on [M] servers.

---

[IF FINDINGS:]

### [MCP-001] [Finding Title]

| Field | Value |
|-------|-------|
| Severity | [CRITICAL / HIGH / MEDIUM / LOW] |
| Tool | `[tool_name]` on server `[server_name]` |
| Check | [Tool Description Poisoning / Tool Name Integrity / Schema Poisoning / Credential Exposure / Capability Mismatch / Tool Shadowing] |
| Vulnerability ID | [VNN — Vulnerability Name] |
| OWASP MCP | [MCPNN — Category Name] |
| Dev Guide Section | [§N — Section Name] |

**Evidence:**
> [Exact text or pattern from the tool definition that triggered this finding]

**Recommendation:** [Specific action — e.g., disconnect server, contact maintainer, remove tool]

---

[Repeat MCP-NNN for each finding]

---

## Checks Performed

| Check | Result |
|-------|--------|
| Tool Description Poisoning | [PASS / N findings] |
| Tool Name Integrity & Unicode | [PASS / N findings] |
| Schema & Parameter Poisoning | [PASS / N findings] |
| Credential & URL Exposure | [PASS / N findings] |
| Capability Mismatch | [PASS / N findings] |
| Tool Shadowing | [PASS / N findings] |

---

## Security Minimum Bar (OWASP GenAI Dev Guide)

| # | Control Area | Status | Notes |
|---|-------------|--------|-------|
| 1 | Strong Identity, Auth & Policy Enforcement | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 2 | Strict Isolation & Lifecycle Control | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 3 | Trusted, Controlled Tooling | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 4 | Schema-Driven Validation Everywhere | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 5 | Hardened Deployment & Continuous Oversight | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |

```
