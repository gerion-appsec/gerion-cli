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
        template = generate_finding_template(metadata)   
        finding_id = str(generate_unique_id([f['File'], str(f['Match']), f['RuleID']]))
        
        # Check if the finding_id has already been processed
        if finding_id not in seen_finding_ids:
            result = {
                'finding_id': finding_id,
                'title': f"Hard coded secret: {f['RuleID']}",
                'description': f['Description'],
                'mitigation': f"Remove the secret ({f['Secret']}) from the code and rotate it",
                'severity': secrets_severity,
                'security_scope': 'Code',
                'scan_type': 'Secrets',
                'file_path': f['File'],
                'line_number': f['StartLine'],
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
                template = generate_finding_template(metadata)   
                finding_id = str(generate_unique_id([e['Target'], f['VulnerabilityID'], str(f['PkgID'])]))
                
                # Check if the finding_id has already been processed
                if finding_id not in seen_finding_ids:
                    result = {
                        'finding_id': finding_id,
                        'title': f"{f['VulnerabilityID']} - {f['PkgID']}",
                        'description': f['Description'],
                        'mitigation': f"Update the package {f['PkgID']} if it has fix. Status: {f['Status']}. Fixed in: {f['FixedVersion'] if 'FixedVersion' in f else 'No fix'}",
                        'severity': f['Severity'],
                        'security_scope': 'Code',
                        'scan_type': 'SCA',
                        'file_path': e['Target'],
                        'component_name': f['PkgName'],
                        'component_version': f['InstalledVersion'],
                        'component_fix': f['FixedVersion'] if 'FixedVersion' in f else None,
                        'cwe': f['CweIDs'] if 'CweIDs' in f else None,
                        'cve': f['VulnerabilityID']
                    }
                    results.append({**template, **result})
                    seen_finding_ids.add(finding_id)  # Mark this finding_id as processed
        
    return results