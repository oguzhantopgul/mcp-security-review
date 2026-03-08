# MCP Security Report Templates

> Three templates for different review contexts. Use Template A for full audits, Template B for quick assessments, Template C for runtime introspection output.

---

## Template A: Full Security Audit Report

*For when source code or full config is provided (Mode 2, full review).*

```markdown
# MCP Security Audit Report

**Target:** [MCP Server Name / Description]
**Review Date:** [YYYY-MM-DD]
**Reviewer:** Claude (MCP Security Review Skill v1.0)
**Input Type:** [Source Code / Config File / Description / URL]
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

## Security Minimum Bar Checklist (OWASP GenAI Dev Guide)

| # | Control Area | Status | Notes |
|---|--------------|--------|-------|
| 1 | Strong Identity, Auth & Policy Enforcement | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 2 | Strict Isolation & Lifecycle Control | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 3 | Trusted, Controlled Tooling | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 4 | Schema-Driven Validation Everywhere | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |
| 5 | Hardened Deployment & Continuous Oversight | [PASS/FAIL/PARTIAL/N/A/CANNOT ASSESS] | [brief note] |

---

## §1 Runtime Manifest Findings (Mode 1)

*[This section contains findings from the automatic runtime tool manifest scan.
If Mode 1 found no issues, state: "No runtime manifest findings." and omit this section.]*

### [MCP-RT-001] [Finding Title]

| Field | Value |
|-------|-------|
| Severity | [CRITICAL / HIGH / MEDIUM / LOW / INFO] |
| Check | [RT-CHECK-01 through RT-CHECK-06] |
| Tool | `[tool_name]` on server `[server_name]` |
| Adversa AI Rank | [#N — Vulnerability Name] |
| OWASP MCP Top 10 | [MCPNN — Category Name] |
| Dev Guide Section | [§N Section Name] |

**Evidence:**
> [Exact text or pattern from the tool definition that triggered this finding]

**Recommendation:**
[Specific, actionable fix. E.g., "Disconnect server X immediately and review source code.
The description at character 847 contains 'ignore all previous instructions' — a clear
tool poisoning indicator (V03). Do not reconnect until the server developer confirms the
description has been sanitized and the version hash verified."]

---

[Repeat MCP-RT-NNN for each runtime finding]

---

## §2 Static Code / Config Findings (Mode 2)

*[This section contains findings from analysis of user-provided source code or config.
Omit if no source was provided.]*

### [MCP-FIND-001] [Finding Title]

| Field | Value |
|-------|-------|
| Severity | [CRITICAL / HIGH / MEDIUM / LOW / INFO] |
| Source | [Static Code / Config / Architecture] |
| Affected Component | [Server / Client / Config / Architecture / Tool Manifest] |
| Adversa AI Rank | [#N — Vulnerability Name] |
| OWASP MCP Top 10 | [MCPNN — Category Name] |
| Dev Guide Section | [§N Section Name] |
| Cheat Sheet Area | [Area Name or N/A] |
| Effort to Fix | [Hours / Days / Weeks / Architecture Change] |

**Description:**
[What is wrong and why it matters in 2-4 sentences.]

**Evidence:**
```[language]
[paste of vulnerable code or config snippet with file:line reference]
```

**Recommendation:**
[Specific, actionable fix with example secure code if applicable.]

---

[Repeat MCP-FIND-NNN for each finding, sorted by severity: Critical → High → Medium → Low → Info]

---

## Framework Coverage Summary

| Framework | Items Checked | Findings Mapped |
|-----------|--------------|-----------------|
| Adversa AI Top 25 | 25 | [N] |
| OWASP MCP Top 10 | 10 | [N] |
| OWASP GenAI Dev Guide | 8 domains | [N] |
| OWASP GenAI Cheat Sheet | 6 areas | [N] |

---

## Prioritized Remediation Roadmap

### 🚨 Immediate (within 24 hours)
*[List Critical findings and their specific fixes. If any Critical findings exist, this server
should NOT be used in production until these are resolved.]*
- [ ] **[MCP-RT-001 / MCP-FIND-001]** — [one-line action]
- [ ] ...

### ⚠️ Short-term (within 1 week)
*[List High findings and their fixes.]*
- [ ] **[MCP-FIND-NNN]** — [one-line action]
- [ ] ...

### 📋 Medium-term (within 1 month)
*[List Medium findings and structural improvements.]*
- [ ] **[MCP-FIND-NNN]** — [one-line action]
- [ ] Implement structured logging and audit trail (C13)
- [ ] Add dependency scanning to CI/CD (C19)

### 🏗️ Long-term (within 3 months)
*[Architecture changes, governance setup, continuous monitoring.]*
- [ ] Establish MCP server governance registry (C21)
- [ ] Implement HITL gates for sensitive tool invocations (C16)
- [ ] Set up continuous tool manifest monitoring with mcp-watch
- [ ] Achieve full Security Minimum Bar compliance

---

## What Was Not Assessed

[List any areas that could not be reviewed due to missing input, and what additional
information would enable that review. Example:]
- **Runtime behavior** — only static analysis was performed; dynamic testing (fuzzing,
  integration tests) was not conducted. Provide a test environment to assess runtime behavior.
- **Network configuration** — deployment infrastructure not provided. Share Docker Compose
  or Kubernetes manifests to assess network binding and segmentation.
- **Authentication backend** — external identity provider not accessible for review.
```

---

## Template B: Quick Risk Assessment

*For when only a description or minimal input is available — a concise 1-page threat model.*

```markdown
# MCP Quick Risk Assessment

**Target:** [MCP Server Name / Description]
**Date:** [YYYY-MM-DD]
**Input:** [Description only / Name only / Partial config]
**Assessment Type:** Threat Model (Limited — no source code reviewed)

---

## Preliminary Risk Rating: [CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN]

*Note: This is a threat model based on [description/name/partial info] only.
A definitive risk rating requires source code or configuration review.*

---

## Key Risk Areas

### [HIGH/MEDIUM/LOW] Risk: [Risk Name]

**Concern:** [What could go wrong based on known patterns for this type of MCP server]
**Likelihood:** [High/Medium/Low given the stated deployment context]
**Framework Reference:** [Adversa #N, OWASP MCPNN]

---

[Repeat for each identified risk area]

---

## Consumer-Side Checklist (OWASP GenAI Cheat Sheet)

Before using this MCP server:
- [ ] **Verify source** — Is this from a trusted, known publisher?
- [ ] **Check version pinning** — Is the version you're using pinned and hash-verified?
- [ ] **Review tool descriptions** — Have tool definitions been scanned for injection patterns?
- [ ] **Assess token scopes** — Are OAuth scopes limited to what is actually needed?
- [ ] **Establish governance** — Is this server in your approved MCP registry?
- [ ] **Plan for revocation** — Can you quickly disconnect this server if a rug pull is detected?

---

## Recommended Next Steps

1. [Most important action]
2. [Second action]
3. [Link to deeper review if source code becomes available]

---

*For a definitive security assessment, share the server's source code or GitHub link
to enable a Full Audit Report (Template A).*
```

---

## Template C: Runtime Tool Manifest Security Summary

*Produced automatically by Mode 1 on every skill activation, before any user input.*

```markdown
# 🔍 Runtime Tool Manifest Security Scan

**Scan Time:** [ISO 8601 timestamp, e.g., 2026-03-08T14:32:00Z]
**Mode:** Automatic Runtime Introspection (Mode 1)
**Scope:** All MCP tools currently connected to this agent

---

## Connected Servers & Tools Inventory

| Server | Tool Count | Capabilities Declared |
|--------|------------|-----------------------|
| [server-name-1] | [N] tools | [filesystem / shell / network / database / comms] |
| [server-name-2] | [N] tools | [network / database] |

**Total:** [N] tools across [M] servers

---

## Scan Results

### [✅ CLEAN / ⚠️ WARNINGS FOUND / 🚨 CRITICAL ISSUES FOUND]

---

[IF CLEAN — use this block:]

✅ **All Clear**

No poisoning indicators, Unicode anomalies, credential exposure, tool shadowing,
or suspicious patterns detected. All [N] tools from [M] connected MCP servers
passed runtime inspection.

---

[IF FINDINGS EXIST — use the blocks below:]

### 🚨 Critical Findings

**[MCP-RT-001] [Finding Title]**

| Field | Value |
|-------|-------|
| Tool | `[tool_name]` |
| Server | `[server_name]` |
| Check | RT-CHECK-01 (Tool Description Poisoning) |
| Vulnerability | V03 — Tool Poisoning |
| Adversa | #3 (Critical 9/10) |
| OWASP MCP | MCP03 |

**Evidence:**
> [Exact text or pattern that triggered the flag — quote the specific text]

**⚠️ Action Required: Disconnect server `[server_name]` immediately and investigate
its source before reconnecting.**

---

### ⚠️ High Findings

**[MCP-RT-002] [Finding Title]**

| Field | Value |
|-------|-------|
| Tool | `[tool_name]` |
| Server | `[server_name]` |
| Check | RT-CHECK-02 (Tool Name Integrity) |
| Vulnerability | V12 — Tool Name Spoofing |

**Evidence:** `[exact tool name with suspicious characters noted]`

**Recommendation:** [Specific action]

---

### ℹ️ Informational

**[MCP-RT-003] [Note]**
- [Description of informational observation]

---

## Checks Performed

| Check | Status | Details |
|-------|--------|---------|
| RT-CHECK-01: Tool Description Poisoning | [✅ PASS / ⚠️ FINDINGS] | [N] tools scanned |
| RT-CHECK-02: Tool Name Integrity & Unicode | [✅ PASS / ⚠️ FINDINGS] | [N] names checked |
| RT-CHECK-03: Schema & Parameter Poisoning | [✅ PASS / ⚠️ FINDINGS] | [N] schemas scanned |
| RT-CHECK-04: Credential & URL Exposure | [✅ PASS / ⚠️ FINDINGS] | [N] definitions scanned |
| RT-CHECK-05: Permission & Capability Assessment | [✅ PASS / ℹ️ NOTE] | [N] tools assessed |
| RT-CHECK-06: Server Count & Shadow Risk | [✅ PASS / ⚠️ FINDINGS] | [M] servers counted |

---

*This scan was performed automatically on skill activation. To perform a deeper review
of any server's source code or configuration, share that material and I will run a full
audit (Mode 2).*
```
