"""
Parsing functionality for security tool outputs.
"""
import hashlib
from datetime import datetime

secrets_severity = 'High'

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
        finding_id = str(generate_unique_id([file_path, str(match_text), rule_id]))
        
        # Check if the finding_id has already been processed
        if finding_id not in seen_finding_ids:
            result = {
                'finding_id': finding_id,
                'title': f"Hard coded secret: {rule_id}",
                'description': description,
                'mitigation': f"Remove the secret ({secret_value}) from the code and rotate it",
                'severity': secrets_severity,
                'security_scope': 'Code',
                'scan_type': 'Secrets',
                'file_path': file_path,
                'line_number': start_line,
                'cwe': ['CWE-798'],
            }
            results.append({**template, **result})
            seen_finding_ids.add(finding_id)  # Mark this finding_id as processed
        
    return results

def parse_sca_tool_output(output, metadata):
    """
    Parses the output of a sca tool and formats it as a set of findings.

    Args:
        output: A list of dictionaries containing sca findings.
        metadata: Metadata about the scan.

    Returns:
        A list of dictionaries representing the unique findings.
    """    
    results = []
    seen_finding_ids = set()
    
    for e in output:
        if 'Vulnerabilities' in e:
            for f in e['Vulnerabilities']:
                # Get package ID safely - try different possible field names
                pkg_id = f.get('PkgID') or f.get('PackageID') or f.get('Package') or f.get('PkgName', 'unknown')
                pkg_name = f.get('PkgName') or f.get('Package') or pkg_id
                installed_version = f.get('InstalledVersion') or f.get('Version') or 'unknown'
                vulnerability_id = f.get('VulnerabilityID') or f.get('CVE') or 'unknown'
                description = f.get('Description') or 'No description available'
                severity = f.get('Severity') or 'Unknown'
                status = f.get('Status') or 'Unknown'
                fixed_version = f.get('FixedVersion') or f.get('FixVersion')
                
                template = generate_finding_template(metadata)   
                finding_id = str(generate_unique_id([e.get('Target', 'unknown'), vulnerability_id, str(pkg_id)]))
                
                # Check if the finding_id has already been processed
                if finding_id not in seen_finding_ids:
                    result = {
                        'finding_id': finding_id,
                        'title': f"{vulnerability_id} - {pkg_name}",
                        'description': description,
                        'mitigation': f"Update the package {pkg_name} if it has fix. Status: {status}. Fixed in: {fixed_version if fixed_version else 'No fix'}",
                        'severity': severity,
                        'security_scope': 'Code',
                        'scan_type': 'SCA',
                        'file_path': e.get('Target', 'unknown'),
                        'component_name': pkg_name,
                        'component_version': installed_version,
                        'component_fix': fixed_version,
                        'cwe': f.get('CweIDs') if 'CweIDs' in f else None,
                        'cve': vulnerability_id
                    }
                    results.append({**template, **result})
                    seen_finding_ids.add(finding_id)  # Mark this finding_id as processed
        
    return results 

def parse_iac_tool_output(output, metadata):
    """
    Parses the output of a Trivy IaC scan and formats it as a set of findings.
    Args:
        output: A list of dictionaries containing IaC findings.
        metadata: Metadata about the scan.
    Returns:
        A list of dictionaries representing the unique findings.
    """
    results = []
    seen_finding_ids = set()
    for e in output:
        if 'Misconfigurations' in e:
            for f in e['Misconfigurations']:
                id_str = f.get('ID') or f.get('RuleID') or f.get('AVDID') or 'unknown'
                title = f.get('Title') or f.get('ID') or 'IaC Misconfiguration'
                description = f.get('Description') or 'No description available'
                severity = f.get('Severity') or 'Unknown'
                status = f.get('Status') or 'Unknown'
                file_path = e.get('Target', 'unknown')
                # First try to get StartLine/Line from the root level
                line = f.get('StartLine') or f.get('Line') or 0
                
                # If not found at root level, try inside CauseMetadata
                # Trivy sometimes returns StartLine and EndLine inside CauseMetadata
                # The structure is: Misconfigurations[].CauseMetadata.StartLine
                if line == 0:
                    cause_metadata = f.get('CauseMetadata', {})
                    if cause_metadata and isinstance(cause_metadata, dict):
                        # Try different possible field names for StartLine
                        if 'StartLine' in cause_metadata:
                            line = cause_metadata['StartLine']
                        elif 'start_line' in cause_metadata:
                            line = cause_metadata['start_line']
                        elif 'startLine' in cause_metadata:
                            line = cause_metadata['startLine']
                        elif 'Line' in cause_metadata:
                            line = cause_metadata['Line']
                        elif 'line' in cause_metadata:
                            line = cause_metadata['line']
                
                # Convert to int if it's a string or number, or use None if not found (0 means not found)
                if line == 0:
                    line = None
                elif line is not None:
                    try:
                        line = int(line)
                    except (ValueError, TypeError):
                        line = None
                template = generate_finding_template(metadata)
                finding_id = str(generate_unique_id([file_path, id_str, title]))
                if finding_id not in seen_finding_ids:
                    result = {
                        'finding_id': finding_id,
                        'title': title,
                        'description': description,
                        'mitigation': f.get('Resolution') or f.get('Message') or 'See documentation.',
                        'severity': severity,
                        'security_scope': 'IaC',
                        'scan_type': 'IaC',
                        'file_path': file_path,
                        'line_number': line,
                        'cwe': f.get('CWE', None),
                        'cve': None
                    }
                    results.append({**template, **result})
                    seen_finding_ids.add(finding_id)
    return results 