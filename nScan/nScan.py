#!/usr/bin/python3

# For network packet manipulation,
# allowing analysis for network scanning.
import scapy.all as scapy
# To access the configuration of the machine's network interfaces
# for determining the scan subnet
import netifaces
import ipaddress

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


# Dictionary to map TTL values to potential OS names.
ttl_os_mapping = {
    64: "Linux/Unix/MacOS/iOS or Android",
    128: "Windows (Generic)",
    255: "Solaris/SunOS or old Unix",
    254: "Cisco Devices",
    60: "Older MacOS or Irix",
    30: "Older Windows or some routers",
    32: "Windows for Workgroups or old Windows 95/98",
}


def get_default_gateway_interface():
    """
    This function finds the default gateway network interface for internet connectivity.
    :return: str name of the default gateway interface
    """
    # Retrieve the default gateways by using netifaces.
    gws = netifaces.gateways()
    return gws['default'][netifaces.AF_INET][1]


def get_ip_subnet():
    """
    This function calculates the network subnet for the default gateway interface.
    If no valid IPv4 address or netmask is found or Error occurs returns None
    :return: The subnet in CIDR notation. Example '192.168.1.0/24' or None
    """
    try:
        # Fetch the default network interface used for the internet connection.
        interface = get_default_gateway_interface()
        # Retrieve all addresses associated with this interface.
        addrs = netifaces.ifaddresses(interface)

        # Check if there are IPv4 addresses associated with interface.
        if netifaces.AF_INET in addrs:
            # Get the first address entry.
            ip_info = addrs[netifaces.AF_INET][0]
            # Extract the IP address and mask from this entry
            ip = ip_info.get('addr')
            netmask = ip_info.get('netmask')

            # Ensure both IP address and netmask are present
            if ip and netmask:
                # Calculate the network address using bitwise AND operation
                ip_binary = scapy.ltoa(scapy.atol(ip) & scapy.atol(netmask))
                # Calculate the CIDR prefix length from the binary representation of netmask
                cidr_prefix_length = sum(bin(scapy.atol(x)).count('1') for x in netmask.split('.'))
                # Return the subnet in CIDR notation.
                return f"{ip_binary}/{cidr_prefix_length}"

    except (KeyError, IndexError, ValueError) as e:
        # Handle exceptions
        print(f"Error IP subnet could not be retrieved: {e}")
    # Return None if no suitable subnet is found
    return None


def get_ttl(ip):
    """
    Fetch the TTL value from the IP header of a response from the given IP
    :param ip: Target IP address.
    :return: int or None: The TTL value, or non if no response.
    """
    try:
        # Construct an ICMP packet.
        packet = scapy.IP(dst=ip) / scapy.ICMP()
        # Send the packet and wait for a response
        response = scapy.sr1(packet, timeout=1, verbose=False)
        if response:
            # Extract and return the TTL from the response.
            return response.ttl
    except scapy.all.TimeoutError:
        # Return non if the request time out.
        return None
    except scapy.all.Scapy_Exception as e:
        print(f"Scapy Exception Occurred: {e}")
        # Return None and print the Scapy Exception.
        return None


def get_os_from_ttl(ttl):
    """
    This function gets the operating system based on its TTL Value.
    :param ttl: TTL value from the IP header.
    :return: str: A string representation of possible operating systems
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


def scan_ports(ip):
    """
    This function scans for open ports on the specified IP address.
    :param ip: Target ip address to scan.
    :return: The list of open ports.
    """
    open_ports = []
    # for loop iterates through previously defined list of ports
    for port in port_to_service.keys():
        # Creating a SYN packet (as part of TCP handshake.)
        packet = scapy.IP(dst=ip) / scapy.TCP(dport=port, flags="S")
        # Sending the packet and waiting for a response.
        response = scapy.sr1(packet, timeout=1, verbose=False)
        # If the SYN-ACK flag set in the response, the port is open.
        if response and response.haslayer(scapy.TCP) and response.getlayer(scapy.TCP).flags == 0x12:
            # Add the port to the list of open ports
            open_ports.append(port)
    # Return the list of open ports.
    return open_ports


def scan_network(ip_range):
    """
    This function scans the network for connected devices and their information over the IP range.
    For IPv4 it uses arp to discover hosts.
    :param ip_range: The target IP range in CIDR notation to scan.
    """
    try:
        # Prepare ARP request for IP range discovery
        arp_request = scapy.ARP(pdst=ip_range)
        # Create an Ethernet broadcast package.
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        # Combine the ARP request with broadcast.
        packet = broadcast / arp_request
        # Send the packet and get the response.
        answered_list = scapy.srp(packet, timeout=1, verbose=False)[0]

        # Define header width for consistent output formatting.
        header_width = 120
        print("~~~ Network Scanning ~~~")
        print("-" * header_width)

        # Process each response received.
        for sent, received in answered_list:
            ip_address = received.psrc
            mac_address = received.hwsrc

            # Obtain the TTL from the IP header to get the OS.
            ttl = get_ttl(ip_address)
            os = get_os_from_ttl(ttl) if ttl else "UNKNOWN"

            # Scan for open ports on the device.
            open_ports = scan_ports(ip_address)
            # Prepare formatted string for open ports.
            ports_info = ', '.join(
                f"{port} ({port_to_service[port]})" for port in open_ports) if open_ports else "Not Found"

            # Gather vulnerability information for open ports.
            vulnerabilities_info = {
                port_to_service[port]: ", ".join(vulnerabilities.get(port_to_service[port], []))
                for port in open_ports
            }
            vulnerabilities_str = "; ".join(
                f"{service}: {cves}" for service, cves in vulnerabilities_info.items() if cves) or "Not Detected"

            # Print detailed info about each detected device.
            print(f"IP Address:     {ip_address}".ljust(20))
            print(f"MAC Address:    {mac_address}".ljust(20))
            print(f"Open Ports:     {ports_info}".ljust(20))
            print(f"OS:             {os}".ljust(20))
            print(f"Vulnerabilities:{vulnerabilities_str}".ljust(20))

            # Print the disclaimer only if there are vulnerabilities detected
            if vulnerabilities_str != "Not Detected":
                print("\nDisclaimer: The vulnerabilities printed does not confirm the actual presence of \n"
                      "these vulnerabilities as patches or specific configurations might have mitigated them.\n"
                      "Further investigation recommended.\n")
            print("-" * header_width)

    except scapy.all.Scapy_Exception as e:
        print(f"Scapy Exception Occurred: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")


def check_connectivity(ip_range):
    """
    This function checks if the system has an active interface within the input IP subnet.
    :param ip_range: IP subnet in CIDR format to check for connectivity
    :return: Returns True if subnet is found. False otherwise.
    """
    try:
        # Convert the input CIDR subnet to an ip_network object for comparison.
        target_subnet = ipaddress.ip_network(ip_range, strict=False)
        # Iterate over all network interfaces of the host system.
        for interface in netifaces.interfaces():
            # Retrieve all addresses
            addresses = netifaces.ifaddresses(interface)
            # Check if there are IPv4 addresses
            if netifaces.AF_INET in addresses:
                # Examine each IPv4 address assigned to the interface.
                for addr_info in addresses[netifaces.AF_INET]:
                    # Convert the address from str format to an ip_address object
                    ip_addr = ipaddress.ip_address(addr_info['addr'])

                    # Check if the IP address belongs to the specified subnet.
                    if ip_addr in target_subnet:
                        # IP in the subnet found.
                        return True

    except ValueError as e:
        # Handle exceptions for invalid IP range inputs
        print(f"Error: Invalid IP range provided - {e}")
    return False  # No matching subnet found.


def main():
    """
    Main function to perform network scanning based on user choice.
    The function first detects the network subnet automatically and then
    offers the user a choice to either scan this auto-detected subnet or
    enter a different one. Depending on the user's input and network connectivity,
    it proceeds to scan the chosen subnet or exits if the user decides not to proceed with an available option.
    """
    # Automatically detect the IP range of the default network interface.
    automated_ip_range = get_ip_subnet()

    # Display options for Network scanning
    print(f"'1' to scan auto detected network {automated_ip_range}")
    print("'2' to scan a different subnet")
    choice = input("Enter your choice (1 or 2): ")

    if choice == '1':
        # Directly scan the auto-detected subnet.
        print(f"Scanning on subnet: {automated_ip_range}")
        scan_network(automated_ip_range)
    elif choice == '2':
        # Prompt for a manual subnet input
        custom_ip_range = input("Please enter the subnet you want to scan! Ex: 192.168.1.0/24: ")
        try:
            # Normalize the IP range to ensure it's a valid network address.
            network = ipaddress.ip_network(custom_ip_range, strict=False)
            custom_ip_range = str(network)
            # Check connectivity to the user-specified subnet.
            if check_connectivity(custom_ip_range):
                # Proceed to scan if the subnet is accessible.
                print(f"Scanning on subnet: {custom_ip_range}")
                scan_network(custom_ip_range)
            else:
                # No connectivity to the provided subnet, offer to continue with the auto-detected subnet
                response = input(
                    f"No connection to the input subnet. Continue with the found subnet {automated_ip_range}? Y/N: ")
                if response.lower() == 'y':
                    print(f"Scanning on subnet: {automated_ip_range}")
                    scan_network(automated_ip_range)
                else:
                    # Exit if the user decides not to proceed.
                    print("Exit nScan.")

        except ValueError as e:
            print(f"Invalid IP range: {e}")
    else:
        # Handle invalid input.
        print("Invalid choice. Exiting.")


if __name__ == "__main__":
    main()
