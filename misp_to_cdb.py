#!/home/wazuh/venv/bin/python3
# -*- coding: utf-8 -*-
from pymisp import ExpandedPyMISP
import os
import warnings

# --- Configuration ---
MISP_URL = 'https://{IP MISP Server}'  # URL ของ MISP Server
MISP_KEY = 'API Key' # API Key จาก MISP
VERIFY_CERT = False

# กำหนดประเภทของ IOCs ที่ต้องการดึงและไฟล์ CDB ที่จะสร้าง
IOC_CONFIG = {
    'ip-dst': '/var/ossec/etc/lists/misp-ips',
    'domain': '/var/ossec/etc/lists/misp-domains',
    'sha256': '/var/ossec/etc/lists/misp-sha256'
}

if not VERIFY_CERT:
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')

def main():
    try:
        misp = ExpandedPyMISP(MISP_URL, MISP_KEY, VERIFY_CERT)
        print("Successfully connected to MISP.")
        for ioc_type, output_file in IOC_CONFIG.items():
            print(f"Fetching attributes of type: {ioc_type}...")
            # ค้นหา attributes ทั้งหมดตามประเภทที่กำหนด
            result = misp.search(controller='attributes', type_attribute=ioc_type, pythonify=True)
            with open(output_file, 'w') as f:
                for attr in result:
                    # เขียนในรูปแบบ CDB list: "key:"
                    f.write(f"{attr.value}:\n")
            print(f"Wrote {len(result)} attributes to {output_file}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
