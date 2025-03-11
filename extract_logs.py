#!/usr/bin/env python3
"""
Extract relevant parts of the log file.
"""

import sys
import re

def extract_error_logs(log_file):
    """Extract error and warning logs from the log file."""
    error_pattern = re.compile(r'(ERROR|WARNING|403|FORBIDDEN|failed|error|warning)', re.IGNORECASE)
    request_pattern = re.compile(r'Request|Response', re.IGNORECASE)
    
    with open(log_file, 'r') as f:
        for line in f:
            if error_pattern.search(line) or request_pattern.search(line):
                print(line.strip())

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <log_file>")
        sys.exit(1)
    
    extract_error_logs(sys.argv[1]) 