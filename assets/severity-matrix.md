# Severity Matrix — MCP Security Review Skill

> Scoring criteria for assigning severity levels to MCP security findings.
> Align with CVSS v3.1, Adversa AI scoring, and MCP-specific context factors.

---

## Severity Levels

### CRITICAL

**CVSS:** ≥ 9.0
**Adversa Score:** 9–10/10

**Criteria (any one qualifies):**
- Enables Remote Code Execution (RCE) with no authentication required
- Enables full authentication bypass (any unauthenticated client can invoke all tools)
- Enables arbitrary data exfiltration from server or connected services
- Enables complete account or session takeover
- Confirmed tool poisoning with active injection directives in tool descriptions

**MCP-Specific Examples:**
- `subprocess.run(user_input, shell=True)` — Command Injection (V02)
- No authentication middleware on any endpoint — Unauthenticated Access (V05)
- Tool description contains `ignore all previous instructions` — Tool Poisoning (V03)
- `eval(user_expression)` with no sandboxing — Remote Code Execution (V04)

**Required Response Time:** Immediate — do not deploy to production until resolved.

---

### HIGH

**CVSS:** 7.0–8.9
**Adversa Score:** 7–8/10

**Criteria (any one qualifies):**
- Significant data exposure (credentials, PII, sensitive business data)
- Privilege escalation (user can access another user's resources)
- Requires only basic conditions to exploit (network access, standard user account)
- Enables lateral movement or persistent access
- Single vulnerability that can be chained to Critical with minimal effort

**MCP-Specific Examples:**
- API key hardcoded in source code — Token/Credential Theft (V08)
- Server binds to `0.0.0.0` — Localhost Bypass/NeighborJack (V13)
- File path input not normalized — Path Traversal (V10)
- OAuth token forwarded without validation — Token Passthrough (V09)
- Tool name contains Cyrillic homoglyphs — Tool Name Spoofing (V12)
- MCP server version unpinned + no hash verification — Rug Pull (V14)

**Required Response Time:** Within 1 week.

---

### MEDIUM

**CVSS:** 4.0–6.9
**Adversa Score:** 5–6/10

**Criteria (any one qualifies):**
- Limited data exposure (non-sensitive data, or exposure requires specific conditions)
- Requires chaining with another vulnerability to cause significant impact
- Defense-in-depth failure (security control is missing, but other controls compensate)
- Affects a subset of users (not all users impacted)
- Exploitability requires attacker to have some existing access

**MCP-Specific Examples:**
- Unpinned dependencies (no version pinning, but no known CVEs) — Rug Pull risk (V14)
- SQL injection in non-public-facing internal tool — SQL Injection (V21)
- Tool with no required fields in schema for a write operation — Schema issue (V11)
- Global mutable dict may leak data in multi-tenant edge cases — Shared State (V25)
- > 5 MCP servers connected simultaneously — Server Count risk (V27)

**Required Response Time:** Within 1 month.

---

### LOW

**CVSS:** 0.1–3.9
**Adversa Score:** ≤ 4/10

**Criteria (any one qualifies):**
- Informational or best-practice deviation with no direct security impact
- Very unlikely to be exploited given the deployment context
- Impact is minimal even if exploited
- Theoretical risk with no demonstrated exploit path

**MCP-Specific Examples:**
- Tool description suspiciously short (< 20 chars) — anomaly, not confirmed threat
- Module-level cache dict (non-user-data) — potential issue only if misused
- Config file uses HTTP for localhost (low risk, but prefer HTTPS everywhere)
- Log verbosity includes non-sensitive parameter names

**Required Response Time:** Within 3 months / ongoing improvement.

---

### INFORMATIONAL

**Criteria:**
- Best practice recommendations with no security impact
- Documentation or hygiene improvements
- Features that could be added to improve observability or resilience

**Examples:**
- Consider adding request ID to audit logs
- Tool descriptions could be more explicit about data handling
- Consider adding rate limiting for additional resilience

---

## Context Adjustment Factors

Severity can be adjusted up or down based on deployment context:

### Increase Severity By One Level If:
- Server is internet-facing (vs. localhost-only)
- Server is multi-tenant (vs. single-user)
- Server handles sensitive data (PII, financial, health)
- Server has elevated privileges (admin, full org access)
- No compensating controls exist

### Decrease Severity By One Level If:
- Server is localhost-only with no network exposure
- Server is behind strong perimeter controls (VPN, firewall)
- Compensating controls make exploitation very difficult
- Server is in a sandboxed/isolated environment
- Finding is in a non-production/test environment

---

## CVSS v3.1 Quick Reference for MCP Findings

| Metric | MCP Context |
|--------|-------------|
| **Attack Vector (AV)** | Network (N) for remote MCP; Local (L) for STDIO/localhost-only |
| **Attack Complexity (AC)** | Low (L) for trivial exploits; High (H) if specific conditions required |
| **Privileges Required (PR)** | None (N) if unauthenticated; Low (L) if any auth required |
| **User Interaction (UI)** | None (N) for automated exploits; Required (R) if agent must be tricked |
| **Scope (S)** | Changed (C) if exploit affects components beyond the MCP server |
| **Confidentiality (C)** | High (H) for credential/data exposure; None (N) for non-data issues |
| **Integrity (I)** | High (H) for code execution, data modification |
| **Availability (A)** | High (H) for DoS-enabling vulnerabilities |

---

## Adversa AI Severity Scale Reference

| Score | Label | Adversa Definition |
|-------|-------|-------------------|
| 10/10 | Critical | Trivially exploitable, catastrophic impact |
| 9/10 | Critical | Easily exploitable, severe impact |
| 8/10 | High | Moderate effort, high impact |
| 7/10 | High | Moderate effort, significant impact |
| 6/10 | Medium | Some complexity, moderate impact |
| 5/10 | Medium | Notable complexity or limited impact |
| 4/10 | Low | High complexity or minimal impact |
| ≤ 3/10 | Low/Info | Theoretical or very limited impact |

---

## Severity Decision Tree

```
Is the vulnerability directly exploitable without authentication?
├── YES → Is impact RCE, full auth bypass, or mass data exfiltration?
│         ├── YES → CRITICAL
│         └── NO  → HIGH
└── NO  → Does it require only low-privilege access to exploit?
          ├── YES → Is impact significant (credential theft, privilege escalation)?
          │         ├── YES → HIGH
          │         └── NO  → MEDIUM
          └── NO  → Is exploitation theoretical or requires complex chaining?
                    ├── YES → LOW or INFORMATIONAL
                    └── NO  → MEDIUM
```

---

## Combined Finding Severity (Multi-Mode Reports)

When a finding appears in BOTH Mode 1 (Runtime) and Mode 2 (Static) for the same server:
- Use the **higher** of the two assessed severities.
- Note both sources in the finding evidence.
- Mark the finding with prefix `MCP-COMBINED-NNN` to indicate multi-mode confirmation.

A finding confirmed by both runtime detection and static analysis is more severe than one detected by only one mode, as it indicates the vulnerability is active (not just theoretical).
