#!/usr/bin/python3

import scapy.all as scapy
import netifaces
import ipaddress
import argparse
import sys

# Dictionary of common services and their associated vulnerabilities as an example
vulnerabilities = {
    'FTP': ['CVE-2011-1234', 'CVE-2011-1500'],
    'SSH': ['CVE-2010-4755', 'CVE-2011-5000'],
    'HTTP': ['CVE-2014-0160', 'CVE-2017-5638'],
    'HTTPS': ['CVE-2016-2107', 'CVE-2018-1312'],
    'SMTP': ['CVE-2020-7247', 'CVE-2011-1720'],
    'POP3': ['CVE-2010-2024', 'CVE-2005-2933'],
    'IMAP': ['CVE-2008-7251', 'CVE-2002-0378'],
    'DNS': ['CVE-2020-1350', 'CVE-2008-1447'],
    'MySQL': ['CVE-2017-3599', 'CVE-2012-2122'],
}

# Dictionary to map port numbers to service names.
port_to_service = {
    21: 'FTP',
    22: 'SSH',
    80: 'HTTP',
    443: 'HTTPS',
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
    53: 'DNS',
    3306: 'MySQL',
}


def get_default_gateway_interface():
    gws = netifaces.gateways()
    return gws['default'][netifaces.AF_INET][1]


def get_ip_subnet():
    try:
        interface = get_default_gateway_interface()
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            ip_info = addrs[netifaces.AF_INET][0]
            ip = ip_info.get('addr')
            netmask = ip_info.get('netmask')
            if ip and netmask:
                ip_binary = scapy.ltoa(scapy.atol(ip) & scapy.atol(netmask))
                cidr_prefix_length = sum(bin(scapy.atol(x)).count('1') for x in netmask.split('.'))
                return f"{ip_binary}/{cidr_prefix_length}"
    except (KeyError, IndexError, ValueError) as e:
        print(f"Error: IP subnet could not be retrieved: {e}")
    return None


def get_ttl(ip):
    try:
        packet = scapy.IP(dst=ip) / scapy.ICMP()
        response = scapy.sr1(packet, timeout=1, verbose=False)
        if response:
            return response.ttl
    except scapy.all.TimeoutError:
        return None
    except scapy.all.Scapy_Exception as e:
        print(f"Scapy Exception Occurred: {e}")
        return None


def get_os_from_ttl(ttl):
    if ttl == 64:
        return "Linux/Unix/MacOS, Android, or iOS"
    elif ttl == 128:
        return "Windows (All versions)"
    elif ttl == 255:
        return "Solaris/SunOS, HP-UX, or old Unix"
    elif ttl == 254:
        return "Cisco network devices"
    elif ttl in (60, 61):
        return "Older MacOS or Irix"
    elif ttl == 30 or ttl == 32:
        return "Older Windows or some routers"
    elif ttl in range(65, 128):
        return "Some type of BSD or customized Linux"
    return "Unknown TTL - Could be a customized setting"


def scan_ports(ip):
    open_ports = []
    for port in port_to_service.keys():
        packet = scapy.IP(dst=ip) / scapy.TCP(dport=port, flags="S")
        response = scapy.sr1(packet, timeout=1, verbose=False)
        if response and response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x12:
            open_ports.append(port)
    return open_ports


def scan_network(ip_range):
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered_list = scapy.srp(packet, timeout=1, verbose=False)[0]

        header_width = 120
        print("~~~ Network Scanning ~~~")
        print("-" * header_width)

        for sent, received in answered_list:
            ip_address = received.psrc
            mac_address = received.hwsrc

            ttl = get_ttl(ip_address)
            os = get_os_from_ttl(ttl) if ttl else "UNKNOWN"

            open_ports = scan_ports(ip_address)
            ports_info = ', '.join(
                f"{port} ({port_to_service[port]})" for port in open_ports) if open_ports else "Not Found"

            vulnerabilities_info = {
                port_to_service[port]: ", ".join(vulnerabilities.get(port_to_service[port], []))
                for port in open_ports
            }
            vulnerabilities_str = "; ".join(
                f"{service}: {cves}" for service, cves in vulnerabilities_info.items() if cves) or "Not Detected"

            print(f"IP Address:     {ip_address}".ljust(20))
            print(f"MAC Address:    {mac_address}".ljust(20))
            print(f"Open Ports:     {ports_info}".ljust(20))
            print(f"OS:             {os}".ljust(20))
            print(f"Vulnerabilities:{vulnerabilities_str}".ljust(20))

            if vulnerabilities_str != "Not Detected":
                print("\nDisclaimer: The vulnerabilities printed do not confirm the actual presence of \n"
                      "these vulnerabilities as patches or specific configurations might have mitigated them.\n"
                      "Further investigation recommended.\n")
            print("-" * header_width)
    except scapy.all.Scapy_Exception as e:
        print(f"Scapy Exception Occurred: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")


def check_connectivity(ip_range):
    try:
        target_subnet = ipaddress.ip_network(ip_range, strict=False)
        for interface in netifaces.interfaces():
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                for addr_info in addresses[netifaces.AF_INET]:
                    ip_addr = ipaddress.ip_address(addr_info['addr'])
                    if ip_addr in target_subnet:
                        return True
    except ValueError as e:
        print(f"Error: Invalid IP range provided - {e}")
    return False


def main():
    parser = argparse.ArgumentParser(description='Network Scanner Tool')
    parser.add_argument('-a', '--auto', action='store_true', help='Automatically scan the detected subnet')
    parser.add_argument('-s', '--subnet', type=str, help='Specify a subnet to scan (e.g., 192.168.1.0/24)')
    args = parser.parse_args()

    if args.auto:
        ip_range = get_ip_subnet()
        if ip_range:
            print(f"Scanning auto-detected subnet: {ip_range}")
            scan_network(ip_range)
        else:
            print("Error: Unable to detect subnet automatically.")
    elif args.subnet:
        try:
            network = ipaddress.ip_network(args.subnet, strict=False)
            ip_range = str(network)
            if check_connectivity(ip_range):
                print(f"Scanning specified subnet: {ip_range}")
                scan_network(ip_range)
            else:
                print(f"No connectivity to the input subnet: {ip_range}")
        except ValueError as e:
            print(f"Invalid IP range: {e}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
