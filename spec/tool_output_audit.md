# Tool Output Audit & Finding Model Evaluation

**Date**: 2026-02-14
**Task**: #9 Audit Tool Outputs
**Status**: Completed

## Executive Summary

We analyzed the raw JSON output of the new tool stack (Opengrep, OSV-Scanner, KICS, Gitleaks) and compared it against the current `gerion_cli.tools.parser` logic.

**Key Findings:**
1. **Tool-specific extras exist** (OWASP categories, references, location detail) but none
   are universally present across all 4 scanners, so they cannot be normalized into the
   shared Finding model without creating sparse, inconsistent data.
2. **Current model is adequate**: The existing fields already capture what matters for
   cross-scanner metrics and API consumption. Adding tool-specific fields would bloat
   the model for marginal value.
3. **No API changes needed**: The `InputFinding`/`Finding` models in `gerion-api-gateway`
   remain valid as-is.

**Decision**: Research complete. No model changes will be implemented.

---

## 1. SAST — Opengrep (was Semgrep)

**Status**: Active & Functional
**Missing Fields in Parser**:

| Field path | Description | Value / Impact |
|------------|-------------|----------------|
| `end.line` | End line of the match | **High**. Allows highlighting the full block, not just the start line. |
| `extra.lines` | Code snippet | **Medium**. Could provide immediate context without reading the file. |
| `extra.metadata.references` | List of URLs | **High**. Links to OWASP, weakness explanation, etc. |
| `extra.metadata.owasp` | OWASP category | **High**. Critical for reporting/dashboarding (e.g. "A03:2021 - Injection"). |
| `extra.metadata.vulnerability_class` | Class name | **Medium**. e.g. "Code Injection", "XSS". Good for grouping. |
| `extra.metadata.confidence` | Confidence level | **Medium**. (LOW/MEDIUM/HIGH). Useful for prioritizing. |
| `extra.metadata.shortlink` | Opengrep rule link | **Low**. Link to rule definition. |

**Recommendation**: No changes. These fields are Opengrep-specific and not present in
other scanners, so they cannot be normalized into the shared Finding model.

---

## 2. SCA — OSV-Scanner (was Trivy/Safety)

**Status**: Active & Functional
**Missing Fields in Parser**:

| Field path | Description | Value / Impact |
|------------|-------------|----------------|
| `vulnerability.references` | List of URLs | **High**. Links to advisories, fixes, mailing lists. |
| `vulnerability.published` | Publish date | **Medium**. "Newness" of the vuln. |
| `vulnerability.modified` | Last modified | **Low**. |
| `package.ecosystem` | Ecosystem (PyPI, npm) | **Medium**. Good for filtering. |

**Recommendation**: No changes. `references` is only present in SCA and SAST (not
Secrets or IaC), and `published_date` is SCA-only. Not universally normalizable.

---

## 3. IaC — KICS (was Checkov/Trivy)

**Status**: Active & Functional
**Note on queries directory**: The KICS binary includes built-in rules. The Dockerfile
creates an empty `/usr/local/bin/assets/queries` directory, which is required for KICS
to start — but the binary falls back to its internal rules when the directory is empty.
This is expected behavior, not a bug.

**Missing Fields in Parser**:

| Field path | Description | Value / Impact |
|------------|-------------|----------------|
| `files.search_key` | Path to config value | **High**. Shows exactly *what* in the file is wrong (e.g. `FROM={{ubuntu:latest}}`). |
| `platform` | Target platform | **Medium**. (Docker, Kubernetes, Terraform). |
| `description_id` | Unique ID | **Low**. |

**Recommendation**: No changes. Fields are KICS-specific and not normalizable across scanners.

---

## 4. Secrets — Gitleaks

**Status**: Active & Functional
**Missing Fields in Parser**:

| Field path | Description | Value / Impact |
|------------|-------------|----------------|
| `EndLine` | End line | **Medium**. Usually secrets are single line, but good for consistency. |
| `StartColumn` | Start col | **Medium**. Precision highlight. |
| `EndColumn` | End col | **Medium**. Precision highlight. |
| `Author`/`Email` | Blame info | **Low**. We capture current commit info via `metadata.py`. Gitleaks blame might be historical, which could be confusing if scanning current working dir. |

---

## Conclusion

After auditing all 4 tool outputs, **no fields were found that are universally present
across all scanners and absent from the current Finding model**. The extra fields each
tool exposes (references, OWASP categories, end_line, ecosystem, search_key) are
tool-specific and cannot be normalized into a shared model without creating sparse,
inconsistent data that wouldn't support meaningful cross-scanner metrics.

The current Finding model and API contract remain adequate. No changes to
`gerion_cli/tools/parser.py` or `gerion-api-gateway` models are needed.
