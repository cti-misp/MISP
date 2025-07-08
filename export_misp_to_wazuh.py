#!/usr/bin/env python3
import warnings
# ปิด FutureWarning / DeprecationWarning ทั้งหมด
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)
# ปิด InsecureRequestWarning เวลาทำ HTTPS request แบบไม่ตรวจ SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import argparse
import sys
from pymisp import ExpandedPyMISP, PyMISPError

def init_misp(url: str, key: str, verify: bool) -> ExpandedPyMISP:
    return ExpandedPyMISP(url, key, verify)

def fetch_sha256_attributes(misp: ExpandedPyMISP) -> list:
    return misp.search(
        controller='attributes',
        type_attribute='sha256',
        pythonify=True
    )

def export_to_wazuh(attrs: list, filepath: str) -> int:
    unique_hashes = set()
    for attr in attrs:
        v = attr.get('value')
        if v:
            unique_hashes.add(v.strip())
    if not unique_hashes:
        return 0
    try:
        with open(filepath, 'w') as f:
            for h in sorted(unique_hashes):
                f.write(f"{h}:\n")
    except:
        return -1
    return len(unique_hashes)

def main():
    parser = argparse.ArgumentParser(
        description="Export SHA256 IoCs from MISP to Wazuh CDB list"
    )
    parser.add_argument('--url',    required=True, help='MISP URL')
    parser.add_argument('--key',    required=True, help='MISP API Key')
    parser.add_argument('--verify', action='store_true', help='Verify SSL')
    parser.add_argument('--output', default='/var/ossec/etc/lists/malware-hashes',
                        help='Output CDB list path')
    args = parser.parse_args()

    try:
        misp = init_misp(args.url, args.key, args.verify)
        attrs = fetch_sha256_attributes(misp)
    except PyMISPError:
        # silent exit on connection/fetch error
        sys.exit(1)

    count = export_to_wazuh(attrs, args.output)
    if count > 0:
        print(f"Export successful: {count} SHA256 hashes to {args.output}")
        sys.exit(0)
    elif count == 0:
        # ไม่มี hash ให้ export
        print("No SHA256 hashes found.")
        sys.exit(2)
    else:
        # เขียนไฟล์ล้มเหลว
        sys.exit(1)

if __name__ == '__main__':
    main()
