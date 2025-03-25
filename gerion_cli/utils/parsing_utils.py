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
        'file_path': None,
        'line_number': None,
        'component_name': None,
        'component_version': None,
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
    # Parse the output and format it as needed
    results = []
    for f in output:
        template = generate_finding_template(metadata)   
        result = {
            'finding_id': str(generate_unique_id([f['RuleID'], f['Description'], str(f['Secret']), f['File']])),
            'title': f"Hard coded secret: {f['RuleID']}",
            'description': f['Description'],
            'mitigation': f"Remove the secret ({f['Secret']}) from the code and rotate it",
            'severity': secrets_severity,
            'security_scope': 'Code',
            'scan_type': 'Secrets',
            'file_path': f['File'],
            'line_number': f['StartLine'],
            'cwe': 798,
        }
        results.append({**template, **result})
        
    return results