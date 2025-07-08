#!/usr/bin/env python3
import argparse
from pymisp import ExpandedPyMISP

def init_misp(url: str, key: str, verify: bool) -> ExpandedPyMISP:
    """
    สร้างการเชื่อมต่อกับ MISP
    """
    return ExpandedPyMISP(url, key, verify)

def fetch_sha256_attributes(misp: ExpandedPyMISP) -> list:
    """
    ดึง Attributes ประเภท SHA256 ทั้งหมดจาก MISP
    """
    return misp.search(
        controller='attributes',
        type_attribute='sha256',
        pythonify=True
    )

def export_to_wazuh(attrs: list, filepath: str):
    """
    เขียนไฟล์ CDB list ให้ Wazuh ใช้งาน
    - แต่ละบรรทัด: "<hash>:"
    - ไม่มีบรรทัดว่างระหว่างรายการ
    - กำจัดค่าซ้ำ และเรียงลำดับก่อนเขียน
    """
    unique_hashes = set()
    for attr in attrs:
        value = attr.get('value')
        if value:
            unique_hashes.add(value.strip())

    with open(filepath, 'w') as f:
        for h in sorted(unique_hashes):
            f.write(f"{h}:\n")

    print(f"Exported {len(unique_hashes)} SHA256 hashes to {filepath}")

def main():
    parser = argparse.ArgumentParser(
        description="Export SHA256 IoCs from MISP to Wazuh CDB list"
    )
    parser.add_argument(
        '--url', required=True,
        help='MISP URL (e.g. https://misp.example.com)'
    )
    parser.add_argument(
        '--key', required=True,
        help='MISP API Key'
    )
    parser.add_argument(
        '--verify', action='store_true',
        help='Verify SSL certificates'
    )
    parser.add_argument(
        '--output', default='/var/ossec/etc/lists/malware-hashes',
        help='Output CDB list path'
    )
    args = parser.parse_args()

    misp  = init_misp(args.url, args.key, args.verify)
    attrs = fetch_sha256_attributes(misp)
    export_to_wazuh(attrs, args.output)

if __name__ == '__main__':
    main()
