#!/usr/bin/env python3
import json
import os
import subprocess
from datetime import datetime
from typing import Dict, List, Set

def load_domains(filename: str = 'domains.txt') -> List[str]:
    """Load domains to monitor from a text file."""
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def load_existing_results(filename: str = 'results.json') -> Dict:
    """Load existing DNSTwist results from JSON file."""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def run_dnstwist(domain: str) -> List[Dict]:
    """Run DNSTwist scan for a single domain."""
    try:
        result = subprocess.run(
            ['dnstwist', '--format', 'json', domain],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error scanning domain {domain}: {e}")
        return []

def compare_results(old_results: Dict, new_results: Dict) -> Set[str]:
    """Compare old and new results to find newly registered domains."""
    old_domains = {
        domain['domain']
        for domain_list in old_results.values()
        for domain in domain_list
        if domain.get('dns-a')  # Only consider domains with A records
    }
    
    new_domains = {
        domain['domain']
        for domain_list in new_results.values()
        for domain in domain_list
        if domain.get('dns-a')  # Only consider domains with A records
    }
    
    return new_domains - old_domains

def main():
    # Load configuration
    domains = load_domains()
    existing_results = load_existing_results()
    
    # Run scans
    new_results = {}
    for domain in domains:
        print(f"Scanning {domain}...")
        new_results[domain] = run_dnstwist(domain)
    
    # Compare results
    new_domains = compare_results(existing_results, new_results)
    
    if new_domains:
        print("\nNew potentially malicious domains detected:")
        for domain in sorted(new_domains):
            print(f"- {domain}")
        
        # Update results file
        with open('results.json', 'w') as f:
            json.dump(new_results, f, indent=2)
        
        # Create or update summary file
        summary = {
            'last_updated': datetime.utcnow().isoformat(),
            'new_domains': sorted(list(new_domains))
        }
        with open('summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Exit with status 1 to indicate changes were detected
        exit(1)
    else:
        print("\nNo new potentially malicious domains detected.")
        exit(0)

if __name__ == '__main__':
    main()