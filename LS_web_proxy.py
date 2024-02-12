"""
IFB102 - Introduction to Computer Systems
Assessment Task 3: Raspberry Pi Mini-Project

LockStock Web Proxy
Version: 1.5
by: Lindsay Fry

Assignment To-do:
	Checkpoint 1:
		- Get Processor working with example requests
			- Make requests 			[X]
			- Display HTTP content 		[X]
			- Cool Terminal UI 			[X]
	
	Checkpoint 2:
		- Migrate to RaspPi 			[X]
		- SSH Utility 					[X]
			- Figure out solution to dynamic addressing [X]
			- Request Tracking [X]

Code To-do:
	- Determine Methods to Implement: [X]
		- POST
		- GET

	- Outgoing and Ingoing request monitoring [X]
	- Arguments for changing Request header (i.e. User-Agent) [X]
	- Arguments for changing Request body (i.e. POST content) [X]
	- Rad UI [X]

"""

import socket,ssl,os,sys
import random,subprocess
from LSExceptions import *

### Global Variables ###

verbose = False

########################


def help_message():
	message=f"""
Usage: 
  ./{sys.argv[0]} <destination>
  ./{sys.argv[0]} [options] <destination>

Monitor web request handshakes.

Options:
  -x, --method		specify request method (GET,POST)
  -q, --quiet			hide welcome banner
  -b, --body			specify body content for POST requests (requires -x POST)
  -t, --timeout		specify timeout period (default is 10 seconds)
  -v, --verbose		display HTML response content in its entirety
  -h, --help			print this help
	"""
	return message

def welcome_banner():
	banner="""
| |-------------------------====================================-------------------------| |
 |     _        ______   ______  _    __  ______  _______  ______   ______  _    __       |
 |    | |      / |  | \\ | |     | |  / / / |        | |   / |  | \\ | |     | |  / /       |
 |    | |   _  | |  | | | |     | |-< <  '------.   | |   | |  | | | |     | |-< <        |
 |    |_|__|_| \\_|__|_/ |_|____ |_|  \\_\\  ____|_/   |_|   \\_|__|_/ |_|____ |_|  \\_\\       |
 |                                                                                        |
 |     _   _   _   ______  ______   ______   ______   ______   _    _  __    _            |
 |    | | | | | | | |     | |  | \\ | |  | \\ | |  | \\ / |  | \\ \\ \\  / / \\ \\  | |           |
 |    | | | | | | | |---- | |--| < | |__|_/ | |__| | | |  | |  >|--|<   \\_\\_| |           |
 |    |_|_|_|_|_/ |_|____ |_|__|_/ |_|      |_|  \\_\\ \\_|__|_/ /_/  \\_\\  ____|_|           |
 |                               (C) Lindsay Fry 2022                                     |
| |-------------------------====================================-------------------------| |     
	"""
	return banner

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

def compose_uri(path_components):
	uri = ""
	for header in path_components:
		uri += "/"+header

	return uri

def grab_url_data(URL):
	# Check if IP or Web Domain

	# Separate URL Method Prefix (http,https) [if provided]
	if "://" in URL:
		hypertext_method,formatted_domain = URL.split("://")
	else:
		hypertext_method = None
		formatted_domain = URL

	# Get URI Path (/path/to/file.html)
	uri_path = formatted_domain.split("/")[1:]

	# Get primary domain (www.test.com)
	formatted_domain = formatted_domain.split("/")[0]

	# Check if port number is included
	try:
		formatted_domain,port = formatted_domain.split(":")
		port = int(port)
	except:
		port = None

	valid_address = True
	is_ip = True
	illegal_chars = r"!@#$%^&*()_+-={}[]|\"':;?/><,`~"
	numbers = "0123456789"
	for character in formatted_domain:
		if character in illegal_chars:
			valid_address = False
		if character != "." and character not in numbers: # Not IP (Fucks up with IPv6)
			is_ip = False

	# If not valid Domain or IP Address
	if not valid_address:
		print(f"[X] Error: Invalid Address: {formatted_domain}")
		exit()

	if is_ip:
		# Swap values as submitted host is raw IP address
		domain_ip = formatted_domain
		formatted_domain = get_ip_domain(domain_ip)
	else:
		domain_ip = get_domain_ip(formatted_domain)

	uri_path = compose_uri(uri_path)

	return hypertext_method,formatted_domain,domain_ip,uri_path,port

def get_domain_ip(domain):
	# Convert Domain to IP
	try:
		print("[-] Grabbing Host IP")
		domain_ip = socket.gethostbyname(domain)
		print("[+] Retrieved IP")
	except:
		print("[X] Error: Couldn't Retrieve IP")
		exit()

	return domain_ip

def get_ip_domain(ip):
	# Convert IP to Domain
	try:
		print("[-] Grabbing Host Domain")
		domain_host = socket.gethostbyaddr(ip)[2][0]
		print("[+] Retrieved Domain")
	except:
		print("[X] Error: Couldn't Retrieve Hostname")
		exit()

	return domain_host

def is_valid_method(method):
	methods = ["GET","POST"]
	if method in methods:
		return True
	return False

def compose_request(destination,uri,request_method,body):
	request = ""
	headers = []

	# Request Headers
	req_method = request_method
	if uri:
		req_path = uri
	else:
		req_path = "/"
	req_version = "HTTP/1.1"
	headers.append(f"{req_method} {req_path} {req_version}")

	req_host = destination
	headers.append(f"Host: {req_host}")

	req_insecure_upgrade = 1
	headers.append(f"Upgrade-Insecure-Requests: {req_insecure_upgrade}")

	req_agent = "LockStock/1.0 (X11; CrOS armv7l 13597.84.0) LockStockWebKit/1.0 (KHTML, like Gecko)"
	headers.append(f"User-Agent: {req_agent}")

	req_accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
	headers.append(f"Accept: {req_accept}")

	req_encoding = "gzip, deflate"
	headers.append(f"Accept-Encoding: {req_encoding}")

	req_language = "en-GB,en;q=0.9"
	headers.append(f"Accept-Language: {req_language}")

	req_connection = "Close"
	headers.append(f"Connection: {req_connection}")

	# Request Body
	if body:
		req_contentlength = len(body)
		headers.append(f"Content-Length: {req_contentlength}")

		req_body = body
		headers.append(f"\r\n{req_body}")

	# Format and compile into string
	for header in headers:
		if header == headers[-1]:
			if request_method == "POST": # Newlines unnecessary after POST body
				request += header
			else:
				request += header+"\r\n"*2
		else:
			request += header+"\r\n"

	return request

def get_status_code(response):
	# HTTP/2 200 OK
	# response = response.decode()
	status_header = response.split("\r\n")[0]
	status_code = status_header.split(" ")[1]
	return status_code

def is_redirect_code(status_code):
	redirect_codes = ["301","302"] # Status codes that require further requests
	if status_code in redirect_codes:
		return True
	return False

def get_header_value(header,response):
	if "bytes" in str(type(response)): # Decode bytes objects
		try:
			response = response.decode()
		except UnicodeDecodeError:
			response = response.decode('latin1')

	header_position = response.find(f"{header}: ") # Find Header Position
	if header_position == -1:
		raise InvalidHeaderError(f"Header '{header}' not present")
		
	eol = response.find("\r\n",header_position) # Find Where Header Line Ends
	
	content = response[header_position+len(header)+2:eol] # offset by +2 to account for " :"

	return content

def get_redirect_location(response):
	global timeout
	# Get Location Header
	location = get_header_value("Location",response)

	return location

def get_response_headers(response):
	header_end = response.find(b"\r\n\r\n")
	return response[:header_end]

def get_response_content(response):
	content_start = response.find(b"\r\n\r\n")+4 # Not even gonna try using \x00 cuz backticks are fucking stupid
	return response[content_start:]

def format_html(raw_html):
	formatted_html = ""
	for char in raw_html:
		formatted_html += char
		if char == ">":
			formatted_html += "\n"

	return formatted_html

def process_request(destination,destination_port,address,uri,request_method,socket_timeout,body=None):
	"""
	Example Output:

	[-] Request Content:
		GET / HTTP/1.1
		Host:			www.test.com
		User-Agent:		LockStock/1.0 (Windows NT 10.0; Win64; x64) LockStockWebKit/1.0 (KHTML, like Gecko)    <- Platform Formatting
		Accept:			gzip, deflate
		Connection:		Close
		Content-Length:	35
	[-] Making Request...
	[+] Request Succeeded || [X] Request Failed
	[-] Reading Response...
	[+] Response Received || [X] Connection Timeout
	[-] Reponse Content:
		<html>
			<head>
				<h1>Hello World!</h1>
			</head>
		</html>
	"""
	
	global verbose

	request_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	
	is_ssl = False
	if not destination_port:
		destination_port = 80
	elif destination_port == 443:
		request_socket = ssl.wrap_socket(request_socket,keyfile=None, certfile=None, server_side=False, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_SSLv23)
		is_ssl = True

	print("[-] Initiating Connection...")
	try:
		request_socket.connect((destination,destination_port))
		if is_ssl:
			print("[+] SSL-Encrypted Connection Established")
		else:
			print("[+] Connection Established")
	except:
		print("[X] Error: Could Not Connect")
		exit()

	# Compose Request
	print("[-] Composing Request...")
	request = compose_request(destination,uri,request_method,body).encode('utf-8')
	print("[+] Request Composed")
	print("[-] Request Content:")
	print(request.decode(),end="")
 
	# Send Request
	print("[-] Sending Request...")
	try:
		request_socket.sendall(request)
		print("[+] Request Succeeded")
	except:
		print("[X] Error: Request Failed")

	# Listen For Response
	request_socket.settimeout(socket_timeout)
	print("[-] Reading Response...")
	try:
		response = b""
		while True:
			chunk = request_socket.recv(4096)
			if len(chunk) == 0:
				break
			response += chunk
		print("[+] Response Received")
	except socket.timeout:
		print("[X] Error: Connection Timeout")
		exit()
	except:
		print("[X] Unknown Error Occured")
		exit()

	# Split headers and content
	headers = get_response_headers(response)
	content = get_response_content(response)

	# Check encoding type
	try:
		encoding = get_header_value('Encoding',response)
		print(f"[-] Content Encoded with {encoding}")
	except InvalidHeaderError: # Not Encoded
		encoding = None
	
	if encoding == "gzip":
		print("[-] Reversing GZIP Encoding")
		# Decompress GZIP Content

		# Write content to temp file
		temp_file = f"tmp_encoded_{random.randint(10000,99999)}"
		with open(temp_file,"wb") as f:
			f.write(content)

		# Decode using GZIP utility
		process = subprocess.Popen(f"gzip -dc {temp_file}",bufsize=0,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True,encoding="cp1252")
		(decoded_content,exec_err) = process.communicate()

		# Delete temp file
		os.system(f"rm -f {temp_file}")

		print("[+] Content Decoded")

	else:
		decoded_content = content.decode()

	try:
		decoded_headers = headers.decode()
		print("[-] Encoding: UTF-8")
	except UnicodeDecodeError:
		decoded_headers = headers.decode("latin1") # Latin1 is the same as ISO-8859-1
		print("[-] Encoding: ISO-8859-1")

	# Output
	print("[-] Response Content:")

	print(decoded_headers)
	if verbose:
		print(format_html(decoded_content))
	else:
		print(f"{format_html(decoded_content[:1000])}...")

	return decoded_headers

	"""
	Process Response

	1. Check Status Code
		- 301 - Moved Permanently:
			- Redirect to domain in Location header
		- 302 - Moved Temporarily:
			- Same as above

	2. Process and Store Cookies

	"""

def main():
	global verbose

	if is_parameter_present("-h","--help") or len(sys.argv) < 2: # Help Message
		print(help_message(),end="")
		exit()
	
	if not is_parameter_present("-q","--quiet"):	# Quiet Mode
		print(welcome_banner())

	if is_parameter_present("-x","--method"):		# Request Method
		try:
			request_method = grab_parameter_value("-x").upper()
		except ParameterError:
			request_method = grab_parameter_value("--method").upper()

		if not is_valid_method(request_method):
			print(f"[X] Error: Invalid Request Method: {request_method}")
			exit()
	else:
		request_method = "GET"

	if is_parameter_present("-t","--timeout"):
		try:
			timeout = int(grab_parameter_value("-t"))
		except ParameterError:
			timeout = int(grab_parameter_value("--timeout"))
		except ValueError:
			print(f"[X] Error: Timeout must be integer value")
			exit()
	else:
		timeout = 10

	request_body = None
	if is_parameter_present("-b","--body"):
		try:
			request_body = grab_parameter_value("-b")
		except ParameterError:
			request_body = grab_parameter_value("--body")

	if is_parameter_present("-v","--verbose"):
		verbose = True

	# Grab destination address information
	http_method,domain,ip,uri_path,port = grab_url_data(sys.argv[-1])

	# Perform initial request
	if request_body:
		http_response = process_request(domain,port,ip,uri_path,request_method,timeout,request_body)
	else:
		http_response = process_request(domain,port,ip,uri_path,request_method,timeout)

	status_code = get_status_code(http_response)
	while is_redirect_code(status_code):
		print(f"[-] Got Redirection Code: {status_code}")
		# Process Status and Redirection
		redirect_location = get_redirect_location(http_response)

		http_method,domain,ip,uri_path,port = grab_url_data(redirect_location)
		print(f"[-] Redirecting to {redirect_location}")

		# Redirect Client
		try:
			http_response = process_request(domain,port,ip,uri_path,request_method,timeout)
			status_code = get_status_code(http_response)
		except Exception as e:
			print(f"[X] Error: Could Not Redirect:\n{e}")
			exit()

if __name__ == "__main__":
	main()
