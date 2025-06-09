
# scanner.py

import nmap


def scan_target(target_ip, port_range='1-1024'):
    scanner = nmap.PortScanner()

    print(f"🔍 Scanning {target_ip} for ports {port_range} using SYN scan (-sS)...")
    try:
        scanner.scan(hosts=target_ip, ports=port_range, arguments='-sS')
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        return {}

    results = {}
    for host in scanner.all_hosts():
        results[host] = []
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port].get('name', 'unknown')
                results[host].append({
                    'port': port,
                    'state': state,
                    'service': service
                })
    return results


# Example usage
if __name__ == "__main__":
    target = input("Enter IP or IP range (e.g. 192.168.1.1 or 192.168.1.0/24): ")
    scan_data = scan_target(target)

    for host, ports in scan_data.items():
        print(f"\n📍 Results for {host}:")
        for entry in ports:
            print(f" - Port {entry['port']} ({entry['service']}): {entry['state']}")