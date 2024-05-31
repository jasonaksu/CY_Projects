#!/bin/bash

function help_options() {

	# Print the help text.
	echo "Welcome to the admino system information script."
	echo "Please follow the following instructions to use it."
	echo	
	echo "Usage instructions:"
	# Available commands and their purposes
	echo "- ./admino.sh -1 <interface>: Shows IP adderess info of a network interface."
	echo "- ./admino.sh -2 Provides hostname information"
	echo "- ./admino.sh -4 <group>: Lists users in a specified group"
	echo "- ./admino,sh -5 <user> <directory> : Count files owned by a user in the specified directory."
	echo "- ./admino.sh -7 <user>: Shows a directory list for the specified user."
	echo "- ./admino.sh -8 Lists IP addresses and number of connections for the system."
}

# Function retrives the IPv4 address of a given newtwork interface
function get_interface_ip() {
    local interface=$1  # Assigns the first argument to 'interface', represcenting the network interface name
    # First, use 'ip addr show' to display information about the network interface.
    # Then, use 'grep' to find lines containing 'inet', filtering out IPv6 addresses which contain 'inet6'.
    # 'awk' is used to print the second field from the matched line, which is the IP address with subnet.
    # Finally, 'cut' is used to split the address by '/' and take the first part, which is the IP address.
    # If the interface does not exist or has no IP assigned, prints an error message.
    ip addr show $interface | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 || echo "Interface not found or no IP assigned"
}

# Function to get  hostname information
function hostname_info() {
	# Using hostnamectl command to get detailed hostname info.
	hostnamectl
}

# Function to list  users into a specific group.
function users_in_group() {
	local group=$1 # Group name.

	# Using 'getent group' to get group info and 'awk' to extract users in the group.
	local users=$(getent group $group | awk -F: '{print $4}')
	# Checks if the users variable is empty. For the scenerio group does not exist or has no members.
	if [ -z "$users" ]; then
		echo "Group not found"
	else
		echo "List of users into group: $group"
		# Formats user list for output readibility
		echo $users | tr ',' '\n' | awk '{print "\t- " $0}'
	fi 
}

# Function to list the number of files own by an specific user from a particular directory.
function list_files() {
	local user=$1
	local directory=$2
	# Using 'find' to count the number of files for the users in the specified directory.
	local file_count=$(find $directory -user $user -type f 2>/dev/null | wc -l)
	# Output message and error handling.
	if [ -d "$directory" ]; then
		echo "This user has a total of $file_count files."
	else
		echo "'$directory' not found or inaccessible."
	fi
}

# Function to get directory list for a user.
function directory_list() {
	local user=$1
	local directory="/home/$user"
	# using tree to display the directory structure for the users home directory.
	if [ -d "$directory" ]; then # Check if the directory exist.
		tree "$directory" || echo "Could not display directory structure for '$user'."
	else
		echo  "User or directory not found"
	fi
}

# Function to list of IPs and number of connections  from where systems user have connected.
function ip_connections() {
	# Header for the output.
echo "(Con.#) (IP add)"
	# Using last -i and awk to list IP adresses and their connections count.
	# Filtering the lines does not contain valid Ip address
	# Sort the IP adresses to group identical addresses together
	# Use uniq -c to count occurences of each IP address, showing the count first
	# Sort the results in reverse order to show most frequent connections at the top.
	last -i | awk '{print $3}' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr
}

# Main script execution starts here.
# Check for the number of arguments.

if [ "$#" -lt 1 ]; then
	echo "Error: No arguments provided."
	# Displays help options to user.
	help_options
	exit 1
fi

# Case statement to handle script arguments.
case "$1" in
	-1)
		if [ "$#" -eq 2 ]; then
			# Retrives and displays the IP address for the specified network interface.
			ip=$(get_interface_ip "$2")
			echo "Your IP for $2 interface is: $ip"
		else
			echo "Usage: $0 -1 <interface>"
			exit 1
		fi
		;;

	-2)
		# Displays detailed hostname information.
		hostname_info
		;;

	-4)
		if [ "$#" -eq 2 ]; then
			# Lists users belonging to a specified group.
			users_in_group "$2"
		else
			echo "Usage: $0 -4 <group>"
        	fi
        	;;

	-5)
		if [ "$#" -eq 3 ]; then
			# Lists the number of files owned by a user in a specified directory.
			list_files "$2" "$3"
		else
			echo "Usage: $0 -5 <user> <directory>"
		fi
		;;

	-7)
		if [ "$#" -eq 2 ]; then
			# Displays the directory structure for a user's home directory.
			directory_list "$2"
		else
			echo "Usage: $0 -7 <user>"
		fi
		;;

	-8)
		# Lists IP addresses and the number of connections from user logins.
		ip_connections
		;;

	*)
		echo
		# Displays help options to user.
		help_options
		;;

esac
