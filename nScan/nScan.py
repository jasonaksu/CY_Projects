#!/usr/bin/python3

import scapy.all as scapy
import netifaces
import ipaddress
import argparse
import logging
from tqdm import tqdm
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

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

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def log_error(message):
    """
    Logs an error message.
    """
    logging.error(message)


def get_default_gateway_interface():
    """
    Retrieves the default gateway network interface for IPv4.
    Returns: str: The default gateway interface name.
    """
    # Get the gateways information.
    gws = netifaces.gateways()
    # Check if there's a default gateway for IPv4.
    if netifaces.AF_INET in gws['default']:
        # Get the interface name.
        interface = gws['default'][netifaces.AF_INET][1]
        logging.info(f"Default gateway interface: {interface}")
        # Return the interface name.
        return interface
    # Return None if no default gateway is found.
    return None


def get_ip_subnet():
    """
    Retrieves the IPv4 subnet based on the default gateway interface information.
    Returns: str: The detected IPv4 subnet in CIDR notation (e.g., '192.168.1.0/24')
    """
    try:
        # Get the default gateway interface and its IP address information  (IPv4)
        interface = get_default_gateway_interface()
        # Get the IP address and netmask of the default gateway interface
        if not interface:
            # Raise an error if no interface is found.
            raise ValueError("No default gateway interface found.")
        # Get addresses associated with the interface.
        addrs = netifaces.ifaddresses(interface)
        # Check if there are IPv4 addresses.
        if netifaces.AF_INET in addrs:
            # Get the first IPv4 address entry.
            ip_info = addrs[netifaces.AF_INET][0]
            # Get the IP address.
            ip = ip_info.get('addr')
            # Get the netmask.
            netmask = ip_info.get('netmask')
            if ip and netmask:
                # Calculate the network address.
                ip_binary = scapy.ltoa(scapy.atol(ip) & scapy.atol(netmask))
                # Calculate the CIDR prefix length.
                cidr_prefix_length = sum(bin(scapy.atol(x)).count('1') for x in netmask.split('.'))
                # Form the subnet in CIDR notation.
                subnet = f"{ip_binary}/{cidr_prefix_length}"
                logging.info(f"Detected IPv4 subnet: {subnet}")
                # Return the subnet.
                return subnet
    except (KeyError, IndexError, ValueError) as e:
        # Log any errors.
        log_error(f"Error: IP subnet could not be retrieved: {e}")
    # Return None if no subnet is found.
    return None


def get_ttl(ip):
    """
    Sends an ICMP request to the target IP and retrieves the TTL value from the response.
    Args: ip (str): The target IP address.
    Returns: int: The TTL value from the response, or None if no response.
    """
    try:
        # Create an ICMP packet to the target IP address.
        packet = scapy.IP(dst=str(ip)) / scapy.ICMP()
        # Send the packet and wait for a response.
        response = scapy.sr1(packet, timeout=1, verbose=False)
        if response:
            # Extract the TTL value from the response.
            ttl = response.ttl
            return ttl
    except scapy.error.Scapy_Exception as e:
        # Log any Scapy exceptions.
        log_error(f"Scapy Exception Occurred: {e}")
        return None


def get_os_from_ttl(ttl):
    """
    Infers the operating system based on the TTL value.
    Args: ttl (int): The TTL value.
    Returns: str: The inferred operating system.
    """
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


def scan_port(ip, port, timeout):
    """
    Scans a specific port on the target IP address.
    Args:
        ip (str): The target IP address.
        port (int): The port number to scan.
        timeout (int): The timeout value for the scan.
    Returns:
        int: The port number if open, or None if closed.
    """
    # Create a TCP SYN packet to the target IP address and port.
    packet = scapy.IP(dst=str(ip)) / scapy.TCP(dport=port, flags="S")
    # Send the packet and wait for a response.
    response = scapy.sr1(packet, timeout=timeout, verbose=False)
    # Check if the response has a SYN-ACK flag, indicating the port is open.
    if response and response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x12:
        return port
    # Return None if the port is closed.
    return None


def scan_ports(ip, timeout):
    """
    Scans multiple ports on the target IP address.
    Args:
        ip (str): The target IP address.
        timeout (int): The timeout value for each port scan.
    Returns: list: A list of open ports.
    """
    # Initialize an empty list to store open ports.
    open_ports = []
    # Use a thread pool to scan ports concurrently.
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Submit scan tasks for each port in the port_to_service dictionary.
        futures = [executor.submit(scan_port, ip, port, timeout) for port in port_to_service.keys()]
        # Iterate over the futures as they complete.
        for future in tqdm(futures, desc=f"Scanning ports on {ip}"):
            result = future.result()
            if result:
                # Add the open port to the list.
                open_ports.append(result)
    # Return the list of open ports.
    return open_ports


def scan_network(ip_range, timeout):
    """
    Scans the network for devices within the specified IP range and collects detailed information about each device.
    Args:
        ip_range (str): The target IP range in CIDR notation (e.g., '192.168.1.0/24').
        timeout (int): The timeout value for each port scan.
    """
    try:
        # Convert the IP range to an ip_network object.
        ip_network = ipaddress.ip_network(ip_range)
        # Create an ARP request packet for the specified IP range.
        arp_request = scapy.ARP(pdst=str(ip_network))
        # Create an Ethernet broadcast packet.
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        # Combine the ARP request with the broadcast packet.
        packet = broadcast / arp_request
        # Send the packet and collect the responses.
        answered_list = scapy.srp(packet, timeout=1, verbose=False)[0]

        # Define the width for printing headers.
        header_width = 120
        print("~~~ Network Scanning ~~~")
        print("-" * header_width)

        # Iterate over the responses received.
        for sent, received in answered_list:
            # Extract the IP address and MAC address from the response.
            ip_address = ipaddress.ip_address(received.psrc)
            mac_address = received.hwsrc

            # Get the TTL value from the IP header to infer the operating system.
            ttl = get_ttl(ip_address)
            os = get_os_from_ttl(ttl) if ttl else "UNKNOWN"

            # Scan for open ports on the device.
            open_ports = scan_ports(ip_address, timeout)
            # Prepare a formatted string for open ports.
            ports_info = ', '.join(
                f"{port} ({port_to_service[port]})" for port in open_ports) if open_ports else "Not Found"

            # Gather vulnerability information for the open ports.
            vulnerabilities_info = {
                port_to_service[port]: ", ".join(vulnerabilities.get(port_to_service[port], []))
                for port in open_ports
            }
            # Prepare a formatted string for the vulnerabilities.
            vulnerabilities_str = "; ".join(
                f"{service}: {cves}" for service, cves in vulnerabilities_info.items() if cves) or "Not Detected"

            # Print detailed information about the device.
            print_device_info(ip_address, mac_address, ports_info, os, vulnerabilities_str)
    except scapy.error.Scapy_Exception as e:
        # Log any Scapy exceptions.
        log_error(f"Scapy Exception Occurred: {e}")
    except Exception as e:
        # Log any other exceptions.
        log_error(f"An error occurred: {e}")


def print_device_info(ip_address, mac_address, open_ports, os, vulnerabilities_str):
    """
    Prints detailed information about a device.
    Args:
        ip_address (str): The IP address of the device.
        mac_address (str): The MAC address of the device.
        open_ports (str): A formatted string of open ports and services.
        os (str): The inferred operating system of the device.
        vulnerabilities_str (str): A formatted string of potential vulnerabilities.
    """
    # Get the current timestamp.
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{'Timestamp:':<20} {timestamp}")
    print(f"{'IP Address:':<20} {ip_address}")
    print(f"{'MAC Address:':<20} {mac_address}")
    print(f"{'Open Ports:':<20} {open_ports}")
    print(f"{'OS:':<20} {os}")
    print(f"{'Vulnerabilities:':<20} {vulnerabilities_str}")
    if vulnerabilities_str != "Not Detected":
        # Print a disclaimer if vulnerabilities are detected.
        print(colored("\nDisclaimer: The vulnerabilities printed do not confirm the actual presence of \n"
                      "these vulnerabilities as patches or specific configurations might have mitigated them.\n"
                      "Further investigation recommended.\n", "red"))
    # Print a separator line.
    print("-" * 120)


def check_connectivity(ip_range):
    """
    Checks if the system has an active network interface within the specified IP subnet.
    Args: ip_range (str): The target IP range in CIDR notation (e.g., '192.168.1.0/24').
    Returns: bool: True if connectivity is found, False otherwise.
    """
    try:
        # Convert the IP range to an ip_network object.
        target_subnet = ipaddress.ip_network(ip_range, strict=False)
        # Iterate over all network interfaces on the system.
        for interface in netifaces.interfaces():
            # Get addresses associated with the interface.
            addresses = netifaces.ifaddresses(interface)
            # Check if the interface has IPv4 addresses.
            if netifaces.AF_INET in addresses:
                # Iterate over all IPv4 addresses of the interface.
                for addr_info in addresses[netifaces.AF_INET]:
                    # Convert the address to an ip_address object.
                    ip_addr = ipaddress.ip_address(addr_info['addr'])
                    # Check if the IP address belongs to the specified subnet.
                    if ip_addr in target_subnet:
                        logging.info(f"Connectivity found for subnet {ip_range} on interface {interface}")
                        # Return True if connectivity is found.
                        return True
    except ValueError as e:
        # Log an error if an invalid IP range is provided.
        log_error(f"Error: Invalid IP range provided - {e}")
    # Return False if no connectivity is found.
    return False


class CustomHelpFormatter(argparse.HelpFormatter):
    """
    Custom formatter for argparse help messages to improve formatting.
    """
    def _format_action_invocation(self, action):
        """
        Formats the action invocation string for display.
        Args: action (argparse.Action): The action object.
        Returns: str: The formatted action invocation string.
        """
        if not action.option_strings:
            # Return the metavar if there are no option strings.
            return self._metavar_formatter(action, action.dest)(1)[0]

        parts = []
        if action.option_strings:
            # Add option strings to parts.
            parts.extend(action.option_strings)

        if action.nargs == 0:
            # Join parts with a comma if no arguments.
            return ', '.join(parts)

        # Join parts with a comma.
        return ', '.join(parts)

    def _get_default_metavar_for_optional(self, action):
        """
        Gets the default metavar for optional arguments.
        Args: action (argparse.Action): The action object.
        Returns: str: The default metavar string.
        """
        return ''


class CustomArgumentParser(argparse.ArgumentParser):
    """
    Custom argument parser to format the help message.
    """
    def format_help(self):
        """
        Formats the help message to include custom formatting.
        Returns: str: The formatted help message.
        """
        # Get the default help text.
        help_text = super().format_help()
        # Replace 'optional arguments:' with 'OPTIONAL ARGUMENTS:' for emphasis.
        help_text = help_text.replace('optional arguments:', 'OPTIONAL ARGUMENTS:')
        return help_text


def main():
    # Create a custom argument parser with a description and custom help formatter.
    parser = CustomArgumentParser(
        description='Network Scanner Tool',
        formatter_class=CustomHelpFormatter
    )
    # Add argument for automatic subnet scanning.
    parser.add_argument('-a', '--auto', action='store_true', help='Auto scan detected subnet')
    # Add argument to specify a subnet to scan, with an empty metavar.
    parser.add_argument('-s', '--subnet', type=str, help='Specify subnet (e.g., 192.168.1.0/24)')
    # Add argument to specify the timeout for port scans, with an empty metavar.
    parser.add_argument('-t', '--timeout', type=int, default=1, help='Port scan timeout (default: 1s)')

    # Parse the command-line arguments.
    args = parser.parse_args()

    # Check if the auto scan option is selected.
    if args.auto:
        # Get the automatically detected IP subnet.
        ip_range = get_ip_subnet()
        if ip_range:
            # Print the detected subnet and start the network scan.
            print(f"Scanning auto-detected subnet: {ip_range}")
            scan_network(ip_range, args.timeout)
        else:
            # Print an error message if the subnet cannot be detected.
            print("Error: Unable to detect subnet automatically.")
            # Show the help message.
            parser.print_help()
    # Check if a specific subnet is provided.
    elif args.subnet:
        try:
            # Validate and convert the provided subnet to an ip_network object.
            network = ipaddress.ip_network(args.subnet, strict=False)
            ip_range = str(network)
            # Check if there is connectivity to the specified subnet.
            if check_connectivity(ip_range):
                # Print the specified subnet and start the network scan.
                print(f"Scanning specified subnet: {ip_range}")
                scan_network(ip_range, args.timeout)
            else:
                # Print an error message if there is no connectivity to the subnet.
                print(f"No connectivity to the input subnet: {ip_range}")
                # Show the help message.
                parser.print_help()
        except ValueError as e:
            # Print an error message if the provided subnet is invalid.
            print(f"Invalid IP range: {e}")
            # Show the help message.
            parser.print_help()
    else:
        # Show the help message if no valid arguments are provided.
        parser.print_help()


if __name__ == "__main__":
    main()
