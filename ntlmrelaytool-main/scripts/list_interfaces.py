import subprocess
import json
import sys
import ctypes
import platform
import os

def is_admin():
    try:
        if platform.system() == 'Windows':
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except:
        return False

def get_windows_interfaces():
    """Get network interfaces using PowerShell"""
    try:
        cmd = 'powershell -Command "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed | ConvertTo-Json"'
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            interfaces = json.loads(result.stdout)
            # Handle single interface case where json.loads returns a dict instead of list
            if isinstance(interfaces, dict):
                interfaces = [interfaces]
            return interfaces
        return []
    except Exception as e:
        print(f"Error getting network interfaces: {e}")
        return []

def list_interfaces():
    """List all available network interfaces"""
    if not is_admin():
        print("\nERROR: Administrator privileges required!")
        print("Please run this script as Administrator/root\n")
        print("Windows: Right-click Command Prompt/PowerShell and select 'Run as administrator'")
        return False

    print("\nScanning for network interfaces...")
    
    try:
        if platform.system() == 'Windows':
            interfaces = get_windows_interfaces()
            if interfaces:
                print("\nAvailable Network Interfaces:")
                print("=" * 60)
                for iface in interfaces:
                    print(f"\nInterface: {iface['Name']}")
                    print("-" * 30)
                    print(f"Description: {iface['InterfaceDescription']}")
                    print(f"Status: {iface['Status']}")
                    print(f"MAC Address: {iface['MacAddress']}")
                    print(f"Link Speed: {iface['LinkSpeed']}")
            else:
                print("No network interfaces found")
        else:
            print("This script currently only supports Windows systems")
            return False
        
        print("\nUsage example:")
        print('python src/main.py capture --interface "Wi-Fi"')
        print('python src/main.py capture --interface "Ethernet"')
        return True
        
    except Exception as e:
        print(f"\nError listing interfaces: {e}")
        print("Make sure you have administrator privileges")
        return False

if __name__ == "__main__":
    sys.exit(0 if list_interfaces() else 1)