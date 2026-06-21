"""
Firewall Log Analyzer
Parses firewall log files and extracts security-relevant events.
"""

import re
import argparse
import pandas as pd
from datetime import datetime
from report_generator import generate_excel_report

# Regex pattern for common firewall log format
# Format: DATE TIME ACTION SRC_IP DST_IP PROTO DST_PORT
LOG_PATTERN = re.compile(
    r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
    r'(\w+)\s+'
    r'(\d+\.\d+\.\d+\.\d+)\s+'
    r'(\d+\.\d+\.\d+\.\d+)\s+'
    r'(\w+)\s+'
    r'(\d+)'
)


def parse_log_file(filepath: str) -> list[dict]:
    """Read and parse each line of a firewall log file."""
    events = []

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            match = LOG_PATTERN.search(line)
            if match:
                events.append({
                    'timestamp': match.group(1),
                    'action': match.group(2).upper(),
                    'src_ip': match.group(3),
                    'dst_ip': match.group(4),
                    'protocol': match.group(5).upper(),
                    'dst_port': int(match.group(6))
                })

    return events


def analyze(events: list[dict]) -> dict:
    """Run basic analysis on parsed events."""
    df = pd.DataFrame(events)

    if df.empty:
        print("No events found. Check your log format.")
        return {}

    total = len(df)
    denied = df[df['action'].isin(['DENY', 'DROP', 'BLOCK'])]
    top_blocked_ips = denied['src_ip'].value_counts().head(10)
    top_ports = denied['dst_port'].value_counts().head(10)

    print(f"\n=== Firewall Log Analysis ===")
    print(f"Total events    : {total}")
    print(f"Denied/Blocked  : {len(denied)}")
    print(f"\nTop blocked source IPs:")
    print(top_blocked_ips.to_string())
    print(f"\nTop targeted ports:")
    print(top_ports.to_string())

    return {'df': df, 'denied': denied}


def main():
    parser = argparse.ArgumentParser(description='Firewall Log Analyzer')
    parser.add_argument('--log', required=True, help='Path to firewall log file')
    args = parser.parse_args()

    print(f"Parsing log file: {args.log}")
    events = parse_log_file(args.log)
    print(f"Found {len(events)} events.")

    result = analyze(events)

    if result:
        output_path = 'output/firewall_report.xlsx'
        generate_excel_report(result['df'], output_path)
        print(f"\nReport saved to: {output_path}")


if __name__ == '__main__':
    main()
