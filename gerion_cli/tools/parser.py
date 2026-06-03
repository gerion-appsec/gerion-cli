"""
Parsing functionality for security tool outputs.
"""
import hashlib
import re
from datetime import datetime

secrets_severity = 'High'

# Premium features are now handled via entry_points (FindingEnricher).

# Aux functions
def generate_finding_template(metadata):
    return {
        'finding_id': None,
        'title': None,
        'description': None,
        'mitigation': None,
        'severity': None,
        'security_scope': None,
        'scan_type': None,
        'repository_name': metadata['repository_name'],
        'branch_name': metadata['branch_name'],
        'build_id': metadata['build_id'],
        'code_path': metadata['code_path'],
        'commit_hash': metadata['commit_hash'],
        'commit_author': metadata['commit_author'],
        'file_path': None,
        'line_number': None,
        'component_name': None,
        'component_version': None,
        'component_fix': None,
        'active': True,
        'mitigated': False,
        'false_positive': False,
        'creation_date': datetime.now().isoformat(),
        'last_update_date': datetime.now().isoformat(),
        'cwe': None,
        'cve': None,
        'mitigated_on_build_id': None,
        'trace': None,
        'confidence': None,
        'reachability': None,
        'risk_score': None,
        'score_breakdown': None
    }

def generate_unique_id(strings):
    # Concatenate all strings in the list
    concatenated_string = ''.join(strings)
    
    # Encode the concatenated string to bytes (required for hashing)
    encoded_string = concatenated_string.encode('utf-8')
    
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()
    
    # Update the hash object with the encoded string
    sha256_hash.update(encoded_string)
    
    # Get the hexadecimal representation of the hash and truncate it to 8 characters
    truncated_hash_hex = sha256_hash.hexdigest()[:12]
    
    return truncated_hash_hex

def redact_text(text, visible_percent=0.3):
    """
    Redacts the middle part of a string, keeping a percentage visible at start and end.
    Total visible is visible_percent of the length.
    """
    if not text or len(text) < 4:
        return text
        
    length = len(text)
    visible_len = int(length * visible_percent)
    if visible_len < 2: visible_len = 2 # Keep at least 1 char on each side if possible
    
    # Split visible length between start and end
    side_len = visible_len // 2
    
    return f"{text[:side_len]}...[REDACTED]...{text[-side_len:]}"

SEVERITY_RANK = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
}

def _resolve_severity(severity_raw: str) -> str:
    severity_map = {
        'CRITICAL': 'CRITICAL',
        'HIGH': 'HIGH',
        'MEDIUM': 'MEDIUM',
        'MODERATE': 'MEDIUM',
        'LOW': 'LOW',
        'UNKNOWN': 'LOW',
        'INFO': 'LOW',
    }
    return severity_map.get((severity_raw or '').upper(), 'LOW')


def _extract_fixed_version(vuln: dict, pkg_name: str, pkg_ecosystem: str) -> str | None:
    matched_affected = None
    for affected in vuln.get('affected', []):
        aff_pkg = affected.get('package', {})
        if aff_pkg.get('name') == pkg_name:
            if pkg_ecosystem and aff_pkg.get('ecosystem') and pkg_ecosystem != aff_pkg.get('ecosystem'):
                continue
            matched_affected = affected
            break

    if not matched_affected:
        return None

    def range_priority(r):
        rtype = r.get('type', '')
        if rtype == 'ECOSYSTEM':
            return 0
        if rtype == 'SEMVER':
            return 1
        return 2

    sorted_ranges = sorted(matched_affected.get('ranges', []), key=range_priority)
    for r in sorted_ranges:
        for event in r.get('events', []):
            if 'fixed' in event:
                return event['fixed']
    return None


def _extract_severity_for_vuln(vuln: dict, pkg_name: str, pkg_ecosystem: str) -> str:
    severity_raw = vuln.get('database_specific', {}).get('severity')

    if not severity_raw:
        for affected in vuln.get('affected', []):
            aff_pkg = affected.get('package', {})
            if aff_pkg.get('name') == pkg_name:
                if pkg_ecosystem and aff_pkg.get('ecosystem') and pkg_ecosystem != aff_pkg.get('ecosystem'):
                    continue
                severity_raw = affected.get('database_specific', {}).get('severity')
                break

    return _resolve_severity(severity_raw)


# Tools parsing functions
def parse_secrets_tool_output(output, metadata):
    """
    Parses the output of a secrets tool and formats it as a set of findings.

    Args:
        output: A list of dictionaries containing secret findings.
        metadata: Metadata about the scan.

    Returns:
        A list of dictionaries representing the unique findings.
    """    
    results = []
    seen_finding_ids = set()
    for f in output:
        # Get fields safely - try different possible field names
        file_path = f.get('File') or f.get('file') or f.get('file_path') or 'unknown'
        match_text = f.get('Match') or f.get('match') or f.get('secret') or 'unknown'
        rule_id = f.get('RuleID') or f.get('rule_id') or f.get('rule') or 'unknown'
        description = f.get('Description') or f.get('description') or 'No description available'
        secret_value = f.get('Secret') or f.get('secret') or f.get('match') or 'unknown'
        start_line = f.get('StartLine') or f.get('start_line') or f.get('line') or 0
        
        template = generate_finding_template(metadata)   
        # CRITICAL: ID must be generated from the RAW secret to ensure deduplication works
        finding_id = str(generate_unique_id([file_path, str(match_text), rule_id]))
        
        # Redact secret for storage/display
        redacted_secret = redact_text(str(secret_value))
        
        # Check if the finding_id has already been processed
        if finding_id not in seen_finding_ids:
            result = {
                'finding_id': finding_id,
                'title': f"Hard coded secret: {rule_id}",
                'description': description,
                # Use redacted secret in mitigation advice
                'mitigation': f"Remove the secret ({redacted_secret}) from the code and rotate it",
                'severity': secrets_severity,
                'security_scope': 'Code',
                'scan_type': 'Secrets',
                'file_path': file_path,
                'line_number': start_line,
                'cwe': ['CWE-798'],
            }
            final_finding = {**template, **result}
            results.append(final_finding)
            seen_finding_ids.add(finding_id)  # Mark this finding_id as processed
        
    return results

_GHSA_DESCRIPTION_KEYS = ('impact', 'details', 'summary')
_GHSA_SKIP_KEYS = {
    'proof of concept', 'poc', 'reproduction',
    'timeline', 'patches', 'workarounds', 'references',
    'for more information', 'credit', 'credits',
    'remediation', 'suggested fix', 'fix',
}

def _parse_ghsa_sections(details: str) -> dict:
    """
    Parse ## / ### sections from a GHSA advisory details field.
    Returns dict of {section_title_lower: content} or {} if no sections found.
    """
    if not details or not re.search(r'^#{1,4}\s+', details, re.MULTILINE):
        return {}

    sections = {}
    current_key = None
    current_lines = []

    for line in details.split('\n'):
        m = re.match(r'^#{1,4}\s+(.+)$', line)
        if m:
            if current_key is not None:
                sections[current_key] = '\n'.join(current_lines).strip()
            current_key = m.group(1).strip().lower()
            current_lines = []
        elif current_key is not None:
            current_lines.append(line)

    if current_key is not None:
        sections[current_key] = '\n'.join(current_lines).strip()

    return sections


def _build_description_from_sections(sections: dict, fallback: str, summary: str) -> str:
    """
    Build a clean description from parsed GHSA sections.
    Priority: impact → details → summary section → fallback details → summary field.
    Skips PoC, timeline, patches and other non-descriptive sections.
    """
    for key in _GHSA_DESCRIPTION_KEYS:
        content = sections.get(key, '').strip()
        if content:
            return content
    return fallback or summary or ''


def _dedup_vuln_details(vuln_details: list) -> list:
    """Deduplicate per-vuln entries by CVE ID, keeping the most severe entry per ID."""
    seen: dict = {}
    for vd in vuln_details:
        vid = vd['id']
        if vid not in seen or vd['_rank'] > seen[vid]['_rank']:
            seen[vid] = vd
    sorted_entries = sorted(seen.values(), key=lambda x: x['_rank'], reverse=True)
    return [{k: v for k, v in entry.items() if k != '_rank'} for entry in sorted_entries]


def parse_sca_tool_output(output, metadata):
    """
    Parses the output of OSV-Scanner, grouped by package. Each finding represents
    one vulnerable package and aggregates all its CVEs, CWEs, computes max severity
    and the unified fix version.
    """
    results = []
    seen_finding_ids = set()

    import os as _os
    repo_root = metadata.get('code_path', '')

    for result_item in output:
        source_path = result_item.get('source', {}).get('path', 'unknown')
        if repo_root and source_path and source_path != 'unknown':
            try:
                rel = _os.path.relpath(source_path, repo_root)
                if not rel.startswith('..'):
                    source_path = rel
            except ValueError:
                pass

        for pkg_wrapper in result_item.get('packages', []):
            pkg = pkg_wrapper.get('package', {})
            pkg_name = pkg.get('name', 'unknown')
            pkg_version = pkg.get('version', 'unknown')
            pkg_ecosystem = pkg.get('ecosystem')

            vulnerabilities = pkg_wrapper.get('vulnerabilities', [])
            if not vulnerabilities:
                continue

            cve_list = []
            cwe_set = set()
            max_severity = 'LOW'
            fix_versions = []
            vuln_descriptions = []
            vuln_details = []

            for vuln in vulnerabilities:
                vuln_id = vuln.get('id', 'unknown')
                aliases = vuln.get('aliases', [])

                cve = next((alias for alias in aliases if alias.startswith('CVE-')), vuln_id)
                if cve not in cve_list:
                    cve_list.append(cve)

                for cwe in vuln.get('database_specific', {}).get('cwe_ids', []):
                    cwe_set.add(cwe)

                severity = _extract_severity_for_vuln(vuln, pkg_name, pkg_ecosystem)
                if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(max_severity, 0):
                    max_severity = severity

                fixed = _extract_fixed_version(vuln, pkg_name, pkg_ecosystem)
                if fixed:
                    fix_versions.append(fixed)

                summary = vuln.get('summary')
                details = vuln.get('details')

                sections = _parse_ghsa_sections(details)
                if sections:
                    desc = _build_description_from_sections(sections, details, summary)
                else:
                    desc = details or summary or f"Vulnerability {vuln_id} in {pkg_name}"
                vuln_descriptions.append((severity, desc))

                cvss = next(
                    (s['score'] for s in vuln.get('severity', []) if s.get('type') == 'CVSS_V3'),
                    next((s['score'] for s in vuln.get('severity', [])), None)
                )
                vuln_details.append({
                    'id': cve,
                    'severity': severity,
                    'summary': summary or f"Vulnerability {vuln_id} in {pkg_name}",
                    'fixed': fixed,
                    'cvss': cvss,
                    '_rank': SEVERITY_RANK.get(severity, 0),
                })

            component_fix = None
            if fix_versions:
                try:
                    from packaging.version import parse as parse_version
                    component_fix = str(max(fix_versions, key=lambda v: parse_version(v)))
                except Exception:
                    component_fix = fix_versions[-1]

            if component_fix:
                try:
                    from packaging.version import parse as parse_version
                    clean_pkg_version = pkg_version.replace('.*', '').replace('*', '')
                    if parse_version(clean_pkg_version) >= parse_version(component_fix):
                        continue
                except Exception:
                    pass

            finding_id = str(generate_unique_id([source_path, pkg_name, pkg_version]))

            if finding_id in seen_finding_ids:
                continue

            n_vulns = len(cve_list)
            title = f"{pkg_name} {pkg_version} — {n_vulns} {'vulnerability' if n_vulns == 1 else 'vulnerabilities'}"

            vuln_descriptions_sorted = sorted(
                vuln_descriptions,
                key=lambda x: SEVERITY_RANK.get(x[0], 0),
                reverse=True
            )
            description = vuln_descriptions_sorted[0][1] if vuln_descriptions_sorted else f"Vulnerable package: {pkg_name}"

            unfixed_count = len(vulnerabilities) - len(fix_versions)
            if component_fix:
                if unfixed_count > 0:
                    mitigation_text = (
                        f"Upgrade {pkg_name} to >= {component_fix} (Current: {pkg_version}). "
                        f"Note: {unfixed_count} of {n_vulns} vulnerabilities have no known fix."
                    )
                else:
                    mitigation_text = f"Upgrade {pkg_name} to >= {component_fix} (Current: {pkg_version}). Fixes all {n_vulns} vulnerabilities."
            else:
                mitigation_text = f"Update {pkg_name} to a non-vulnerable version. No known fix available for {n_vulns} vulnerabilities."

            template = generate_finding_template(metadata)
            result = {
                'finding_id': finding_id,
                'title': title,
                'description': description,
                'mitigation': mitigation_text,
                'severity': max_severity,
                'security_scope': 'Code',
                'scan_type': 'SCA',
                'file_path': source_path,
                'component_name': pkg_name,
                'component_version': pkg_version,
                'component_fix': component_fix,
                'cwe': sorted(cwe_set),
                'cve': cve_list,
                'vuln_details': _dedup_vuln_details(vuln_details),
            }

            final_finding = {**template, **result}
            results.append(final_finding)
            seen_finding_ids.add(finding_id)

    return results

def parse_sast_tool_output(output, metadata):
    """
    Parses the output of a SAST tool (Opengrep) and formats it as a set of findings.
    
    Args:
        output: List of Opengrep result objects.
        metadata: Metadata about the scan.
    """
    results = []
    seen_ids = set()
    
    for item in output:
        # Opengrep specific fields
        rule_id = item.get('check_id', 'unknown')
        file_path = item.get('path', 'unknown')
        start_line = item.get('start', {}).get('line', 0)
        extra = item.get('extra', {})
        message = extra.get('message', 'No description available')
        severity_raw = extra.get('severity', 'UNKNOWN').upper()
        
        # Normalize Severity
        severity_map = {
            'ERROR': 'HIGH',
            'CRITICAL': 'CRITICAL',
            'WARNING': 'MEDIUM',
            'INFO': 'LOW'
        }
        severity = severity_map.get(severity_raw, 'MEDIUM') # Default to Medium if unknown
        fix = extra.get('fix', None)
        cwe_list = extra.get('metadata', {}).get('cwe', [])
        if isinstance(cwe_list, str): cwe_list = [cwe_list]
        
        # Unique ID
        finding_id = str(generate_unique_id([file_path, str(start_line), rule_id]))
        
        if finding_id not in seen_ids:
            template = generate_finding_template(metadata)
            result = {
                'finding_id': finding_id,
                'title': f"{rule_id}",
                'description': message,
                'mitigation': f"Fix suggested: {fix}" if fix else "Review code logic.",
                'severity': severity,
                'security_scope': 'Code',
                'scan_type': 'SAST',
                'file_path': file_path,
                'line_number': start_line,
                'component_name': rule_id.split('.')[-1] if '.' in rule_id else rule_id, # Rough component
                'component_version': None,
                'component_fix': None,
                'cwe': cwe_list,
                'cve': None
            }
            
            final_finding = {**template, **result}
            
            # Preserve reachability if already set by StructuralEngine
            if 'reachability' in item:
                 final_finding['reachability'] = item['reachability']
            if 'confidence' in item:
                 final_finding['confidence'] = item['confidence']
            if 'trace' in item:
                 final_finding['trace'] = item['trace']
            
            results.append(final_finding)
            seen_ids.add(finding_id)
            
    return results

def parse_iac_tool_output(output, metadata):
    """
    Parses the output of a KICS IaC scan and formats it as a set of findings.
    Args:
        output: A list of KICS query objects (from the 'queries' key).
        metadata: Metadata about the scan.
    Returns:
        A list of dictionaries representing the unique findings.
    """
    results = []
    seen_finding_ids = set()
    
    for query in output:
        # Query level fields
        query_name = query.get('query_name', 'Unknown Query')
        query_id = query.get('query_id', 'unknown')
        severity_raw = query.get('severity', 'INFO').upper()
        description = query.get('description', 'No description available')
        query_category = query.get('category', 'IaC')
        
        # Map Severity
        severity_map = {
            'CRITICAL': 'CRITICAL',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'LOW': 'LOW',
            'INFO': 'LOW',
            'TRACE': 'LOW'
        }
        severity = severity_map.get(severity_raw, 'LOW')
        
        # Iterate over files where this query matched
        for f in query.get('files', []):
            file_path = f.get('file_name', 'unknown')
            line = f.get('line', 0)
            issue_type = f.get('issue_type', 'unknown')
            expected_value = f.get('expected_value', 'See documentation')
            actual_value = f.get('actual_value', 'unknown')
            
            # Create unique ID
            finding_id = str(generate_unique_id([file_path, query_id, str(line)]))
            
            if finding_id not in seen_finding_ids:
                template = generate_finding_template(metadata)
                
                result = {
                    'finding_id': finding_id,
                    'title': query_name,
                    'description': f"{description}\nIssue Type: {issue_type}",
                    'mitigation': f"Expected: {expected_value}",
                    'severity': severity,
                    'security_scope': 'IaC',
                    'scan_type': 'IaC',
                    'file_path': file_path,
                    'line_number': line,
                    'component_name': query_category, # Use category as component name
                    'component_version': None,
                    'component_fix': None,
                    'cwe': None, # KICS usually doesn't provide CWE in JSON output directly easily mapping
                    'cve': None
                }
                
                results.append({**template, **result})
                seen_finding_ids.add(finding_id)
                
    return results 