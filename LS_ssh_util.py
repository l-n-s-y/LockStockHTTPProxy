"""
IFB102 - Introduction to Computer Systems
Assessment Task 3: Raspberry Pi Mini-Project

LockStock SSH-enabled Remote-Access Utility
Version: 2.0
by: Lindsay Fry
"""

import os,sys
import paramiko
from LSExceptions import *

executable_path = "/home/pi/LS_web_proxy.py"

def welcome_banner():
	banner = "---=== LockStock Remote SSH Utility ===---\n"
	return banner

def help_message():
	message=f"""
Usage: 
  ./{sys.argv[0]} <proxy-destination> <request-destination>
  ./{sys.argv[0]} [connection-options] <proxy-destination> <request-destination>
  ./{sys.argv[0]} [connection-options] [request-options] <proxy-destination> <request-destination>

Connect to remote lockstock proxy instance.

Connection Options:
  -u, --user 		specify username to remotely connect with
  -p, --pkey		specify private key file to remotely connect with
  -q, --quiet		hide welcome banner
  -h, --help		print this help

Request Options:
  -x, --method		specify request method (GET,POST)
  -q, --quiet			hide welcome banner
  -b, --body			specify body content for POST requests (requires -x POST)
  -t, --timeout		specify timeout period (default is 10 seconds)
  -v, --verbose		display HTML response content in its entirety
	"""
	return message

def is_parameter_present(parameter_prefix,parameter_full=None):
	# Check if parameter or set of parameters is present in argv
	if parameter_prefix in sys.argv:
		return True
	if parameter_full in sys.argv:
		return True
	return False

def grab_parameter_value(parameter,instance=1):
	# Grab value directly after n instance of parameter in argv
	instance_count = instance-1 # keeps track of current parameter instance
	for i in range(len(sys.argv)):
		if sys.argv[i] == parameter:
			if instance_count == 0:
				try:
					return sys.argv[i+1]
				except IndexError:
					print(f"[X] Error: supply value for {sys.argv[i]}")
					exit()
			else:
				instance_count -= 1
	raise ParameterError(f"Parameter {parameter} not supplied")

def is_valid_ip(address):
	# Check if IP or Web Domain
	valid_address = True
	is_ip = True
	illegal_chars = r"!@#$%^&*()_+-={}[]|\"':;?/><,`~"
	numbers = "0123456789"
	for character in address:
		if character in illegal_chars:
			valid_address = False
		if character != "." and character not in numbers: # Not valid IPv4 address (Don't ask me about IPv6)
			is_ip = False

	# If not valid Domain or IP Address
	if not valid_address or not is_ip:
		return False

	return True

def main():
	########################## SSH Options ################################

	if is_parameter_present("-h","--help") or len(sys.argv)<2:
		print(help_message(),end="" )
		exit()

	# Grab SSH username
	if is_parameter_present("-u","--user"):
		try:
			username = grab_parameter_value("-u")
		except ParameterError:
			username = grab_parameter_value("--user")

	# Grab SSH password
	if is_parameter_present("-p","--pkey"):
		try:
			private_key_path = grab_parameter_value("-p")
		except ParameterError:
			private_key_path = grab_parameter_value("--pkey")

	# Grab RaspPi Proxy Address
	# if is_parameter_present("-P","--proxy"):
	if is_valid_ip(sys.argv[-2]):
		proxy_destination = sys.argv[-2]
	else:
		print(f"[X] Error: Invalid Proxy Address: {sys.argv[-2]}")
		exit()


	if not is_parameter_present("-q","--quiet"):
		print(welcome_banner())

	########################################################################

	########################## Proxy Options ###############################
	
	# Combine Connection Options
	connection_options = ""

	# Grab Request Method Type
	if is_parameter_present("-x","--method"):
		try:
			method = grab_parameter_value("-x")
		except ParameterError:
			method = grab_parameter_value("--method")
		connection_options += f"-x {method} "

	# Grab POST body content
	if is_parameter_present("-b","--body"):
		try:
			body = grab_parameter_value("-b")
		except ParameterError:
			body = grab_parameter_value("--body")

		connection_options += f"-b '{body}' "

	# Grab Request Timeout value
	if is_parameter_present("-t","--timeout"):
		try:
			timeout = grab_parameter_value("-t")
		except ParameterError:
			timeout = grab_parameter_value("--timeout")

		connection_options += f"-t {timeout} "

	########################################################################

	request_destination = sys.argv[-1] # Webhost destination to send requests towards

	try:
		key = paramiko.RSAKey.from_private_key_file(private_key_path)
	except UnboundLocalError:
		print("[X] Error: Private Key File Not Supplied")
		exit()

	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	# client.load_system_host_keys()

	print("[-] Connecting to Pi...")
	try:
		client.connect(proxy_destination,username=username,pkey=key)
		print("[+] Connection Successful")
	except:
		print("[X] Error: Couldn't Connect to Pi")
		exit()

	# Initial Command Execution
	execution_string = f"python3 {executable_path} {connection_options}{request_destination}"
	stdin, stdout, stderr = client.exec_command(execution_string)

	# Output STDOUT/STDERR contents based on program execution
	stdout_contents = stdout.read().decode('utf-8')
	stderr_contents = stderr.read().decode('utf-8')
	if len(stderr_contents) == 0:
		print(stdout_contents)
	else:
		print(f"[X] Error: {stderr_contents}")
		exit()

	print(f"[-] Exited with status: {stdout.channel.recv_exit_status()}")

	# Close STD File Descriptors
	stdin.close()
	stdout.close()
	stderr.close()

	print("[-] Severed Connection to Pi")
	client.close() # Close Client Connection

if __name__ == "__main__":
	main()