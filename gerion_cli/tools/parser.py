"""
Parsing functionality for security tool outputs.
"""
import hashlib
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

def parse_sca_tool_output(output, metadata):
    """
    Parses the output of OSV-Scanner and formats it as a set of findings.

    Args:
        output: A list of result objects from OSV-Scanner (the 'results' list).
        metadata: Metadata about the scan.

    Returns:
        A list of dictionaries representing the unique findings.
    """    
    results = []
    seen_finding_ids = set()
    
    # Iterate over file results
    for result_item in output:
        # OSV-Scanner 1.5+ structure: "source": {"path": "..."}
        source_path = result_item.get('source', {}).get('path', 'unknown')
        
        # Iterate over packages in the file
        for pkg_wrapper in result_item.get('packages', []):
            pkg = pkg_wrapper.get('package', {})
            pkg_name = pkg.get('name', 'unknown')
            pkg_version = pkg.get('version', 'unknown')
            pkg_ecosystem = pkg.get('ecosystem')
            
            # Iterate over vulnerabilities for the package
            for vuln in pkg_wrapper.get('vulnerabilities', []):
                vuln_id = vuln.get('id', 'unknown')
                aliases = vuln.get('aliases', [])
                
                # 1. Description Logic: Details > Summary > ID
                summary = vuln.get('summary')
                details = vuln.get('details')
                description = details if details else (summary if summary else f"Vulnerability {vuln_id} detected in {pkg_name}")
                
                # 2. Package Matching Logic: Find correct affected entry
                # We need to find the 'affected' block that corresponds to THIS package (name & ecosystem)
                matched_affected = None
                for affected in vuln.get('affected', []):
                    aff_pkg = affected.get('package', {})
                    if aff_pkg.get('name') == pkg_name:
                         # Ideally also check ecosystem if available
                         if pkg_ecosystem and aff_pkg.get('ecosystem') and pkg_ecosystem != aff_pkg.get('ecosystem'):
                             continue
                         matched_affected = affected
                         break
                
                # If no strict match found (unlikely in OSV-Scanner output), fallback to first or none? 
                # OSV-Scanner guarantees the package is affected, so we might just use the first one if name match fails?
                # But let's stick to name match to be safe.
                
                fixed_version = None
                affected_severity = None
                
                if matched_affected:
                    # Extract severity from affected package if present (database_specific)
                    affected_severity = matched_affected.get('database_specific', {}).get('severity')
                    
                    # Extract fixed version
                    for r in matched_affected.get('ranges', []):
                        for event in r.get('events', []):
                            if 'fixed' in event:
                                fixed_version = event['fixed']
                                break
                        if fixed_version: break

                # 3. Severity Logic: database_specific > matched_affected specific > CVSS > default
                severity_raw = vuln.get('database_specific', {}).get('severity')
                
                # If no top-level severity, check affected-level
                if not severity_raw and affected_severity:
                    severity_raw = affected_severity
                
                severity_map = {
                    'CRITICAL': 'CRITICAL',
                    'HIGH': 'HIGH',
                    'MEDIUM': 'MEDIUM',
                    'MODERATE': 'MEDIUM',
                    'LOW': 'LOW',
                    'UNKNOWN': 'LOW',
                    'INFO': 'LOW'
                }
                
                # Severity Logic: database_specific > matched_affected specific > CVSS > default
                severity_raw = vuln.get('database_specific', {}).get('severity')
                
                # If no top-level severity, check affected-level
                if not severity_raw and affected_severity:
                    severity_raw = affected_severity
                
                severity_map = {
                    'CRITICAL': 'CRITICAL',
                    'HIGH': 'HIGH',
                    'MEDIUM': 'MEDIUM',
                    'MODERATE': 'MEDIUM',
                    'LOW': 'LOW',
                    'UNKNOWN': 'LOW',
                    'INFO': 'LOW'
                }
                
                if severity_raw:
                    severity = severity_map.get(severity_raw.upper(), 'LOW')
                else:
                    severity = 'LOW' # Default fallback
                
                # Version Comparison for Mitigation Context
                is_false_positive_candidate = False
                try:
                    from packaging.version import parse as parse_version
                    # Clean wildcard versions (e.g. 0.30.* -> 0.30)
                    clean_pkg_version = pkg_version.replace('.*', '').replace('*', '')
                    if fixed_version:
                        if parse_version(clean_pkg_version) >= parse_version(fixed_version):
                            is_false_positive_candidate = True
                except ImportError:
                    pass # packaging not available, skip check
                except Exception:
                    pass # Version parsing failed, skip check

                # CVE Extraction (prefer CVE alias)
                cve = next((alias for alias in aliases if alias.startswith('CVE-')), vuln_id)
                
                template = generate_finding_template(metadata)   
                # Unique ID based on file, vuln ID, package, and version
                finding_id = str(generate_unique_id([source_path, vuln_id, pkg_name, pkg_version]))
                
                # Check if the finding_id has already been processed
                if finding_id not in seen_finding_ids:
                    
                    mitigation_text = f"Update {pkg_name} to a non-vulnerable version."
                    if fixed_version:
                         mitigation_text = f"Fixed in {fixed_version} (Current: {pkg_version})"
                         if is_false_positive_candidate:
                             mitigation_text += " - POSSIBLE FALSE POSITIVE: Current version appears newer than fix."

                    result = {
                        'finding_id': finding_id,
                        'title': f"{vuln_id} - {pkg_name}",
                        'description': description,
                        'mitigation': mitigation_text,
                        'severity': severity,
                        'security_scope': 'Code',
                        'scan_type': 'SCA',
                        'file_path': source_path,
                        'component_name': pkg_name,
                        'component_version': pkg_version,
                        'component_fix': fixed_version,
                        'cwe': vuln.get('database_specific', {}).get('cwe_ids', []),
                        'cve': cve
                    }

                    if is_false_positive_candidate:
                         # Skip adding this finding as it is a false positive
                         continue

                    final_finding = {**template, **result}
                    results.append(final_finding)
                    seen_finding_ids.add(finding_id)  # Mark this finding_id as processed
        
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