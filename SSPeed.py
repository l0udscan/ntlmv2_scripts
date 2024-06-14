#!/usr/bin/python

# Script Title: SSPeed - NTLM SSP message identifier and decoder (v1.0)
# Date: 06/07/2024
# Script Author: Louden Demers
#Use Case:
	#For NTLMv2 Base64 encoded message acquired by packet sniffing or HTTP response/request interception on an insecure login page.
	#Can take a single NTLMv2 Base64 encoded message of any type and identify it, then extract the values for learning.
	#Can take a full authentication session (Type 1, Type 2, and Type 3 message) and craft a "hash" for cracking tools like Hashcat or John the Ripper

#TODO: 
# Add functionality to perform the authentication from the script (this would be for testing, as the user's goal is to get the password)
	#Add extra command-line args for user/pass combination
	#Add -h for "Help"
	#Add -i <single_NTLMv2_message>
	#Add -m for "Multi-Message" mode in case a user doesn't want to authenticate from here. This will accept only the three Base64 items.
	#Add -u <user>
	#Add -p <password>
# Add functionality to pull the requests and responses from the script (without needing Burp, Wireshark, TCPDump, etc.)

import base64
import sys
import struct
import time
import shutil
import hashlib
import hmac
import random
import binascii
import os
#import pyfiglet

#Initial Banner Printing
#TODO: Fix the resizing for smaller terminals
def print_banner() :
	#TODO: Implement later
	def get_terminal_width():
		return os.get_terminal_size().columns

	#Get terminal size stuff, not really used atp
	terminal_size = shutil.get_terminal_size((80, 20))
	terminal_width = get_terminal_width()
	width = terminal_size.columns

	#Banner looks absolutely disgusting in the text editor
	banner = """
 ░▒▓███████▓▒░▒▓███████▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓████████▓▒░▒▓███████▓▒░  
░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓██████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░     ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░     ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░▒▓███████▓▒░░▒▓█▓▒░      ░▒▓████████▓▒░▒▓████████▓▒░▒▓███████▓▒░  
\t\t\t\t\t\t\t\t\tv1.0
	"""
	
	#TODO: Implement smaller banner for smaller terminal
	small_text = "SSPeed"
	#banner_small = pyfiglet.figlet_format(small_text, font="slant")
	
	#TODO: Logic for automatic banner resizing
	if terminal_width < 80:
		#print(colors.CYAN + banner_small.center(width) + colors.RESET)
		print("NOT IMPLEMENTED")
	else:
		print(colors.CYAN + banner.center(width) + colors.RESET)

#Used to format the hash in Multi-Message Mode
def format_hash(username, domain, server_challenge, NTProof, blob):
	#Handles the logic flow for a lack of domain
	if not domain:
		#Clean up the extracted values and get rid of unnecessary whitespace
		username_clean = username.strip()
		server_challenge_clean = server_challenge.strip()
		NTProof_response_clean = NTProof.strip()
		blob_clean = blob.strip()
		
		#Output formatted hash
		print("\n~~~Formatted Hash (for cracking):")
		print(f"{username_clean}:::{server_challenge_clean}:{NTProof_response_clean}:{blob_clean}")
	elif len(domain) > 0:
		username_clean = username.strip()
		domain_clean = domain.strip()
		server_challenge_clean = server_challenge.strip()
		NTProof_response_clean = NTProof.strip()
		blob_clean = client_challenge.strip()
		
		print("\n~~~Possible Hash Formats (for cracking):")
		print(f"{username_clean}::{domain_clean}:{server_challenge_clean}:{NTProof_response_clean}:{blob_clean}")
	else:
		print("ERROR: There is a missing value")

#Handles NTLM Type 1 Message (Client Response requesting NTLM auth)
def parse_ntlm_type1_message(mode, binary_message):
	#Extract ASCII characters and bytes from binary message
	signature = binary_message[0:8].decode('ascii')
	message_type = int.from_bytes(binary_message[8:12], 'little')
	flags = int.from_bytes(binary_message[12:16], 'little')
	
	#Multi-Message Mode (2) Execution Path
	if mode == 2 and message_type != 1:
		print("ERROR: Incorrect message supplied as argument!")
		sys.exit(1)
	#Fancy "Resolving........" message
	elif message_type != 1:
		print("\nMessage type = ", message_type)
		print("\nResolving", end = '', flush = True)
		for _ in range(18):
			time.sleep(0.08)
			print('.', end = '', flush = True)
	
	#Return extracted values as dictionary
	return {
		"signature": signature,
		"message_type": message_type,
		"flags": flags,
	}

#Handles NTLM Type 2 Message (Server Challenge)	
def parse_ntlm_type2_message(binary_message):
	#Extract ASCII characters and bytes from binary message
	signature = binary_message[0:8].decode('ascii')
	message_type = int.from_bytes(binary_message[8:12], 'little')
	
	#Unpack binary data (struct library came in clutch here BIG TIME)
	target_name_length = struct.unpack('<H', binary_message[12:14])[0] #Unpack unsigned short int (H) with little-endian order (<)
	target_name_max_length = struct.unpack('<H', binary_message[14:16])[0]
	target_name_offset = struct.unpack('<I', binary_message[16:20])[0] #Unpack unsigned int (I) with little-endian order (<)
	
	flags = struct.unpack('<I', binary_message[20:24])[0]
	
	#Randomly-generated Server Challenge
	nonce = binary_message[24:32]
	server_nonce_hex = nonce.hex()
	
	#Return extracted values as dictionary
	return {
		"signature": signature,
		"message_type": message_type,
		"target_name_length": target_name_length,
		"target_name_max_length": target_name_max_length,
		"target_name_offset": target_name_offset,
		"flags": flags,
		"server_nonce": server_nonce_hex,
	}
	
#Handles NTLM Type 3 Message (Client Response sending hashed challenge)
def parse_ntlm_type3_message(binary_message):

	#List of AVIDs. An AVID is a 16-bit identifier specifying the type of attribute. 
	AV_IDS = {
		0x0000: "MsvAvEOL",					#Signifies the end of the AV_PAIR list. Acts as a terminator.
		0x0001: "MsvAvNbComputerName",	#Contains the NetBIOS name of theserver that is responding to the authentication request.
		0x0002: "MsvAvNbDomainName",		#Contains the NetBIOS domain name of the domain to which the server belongs.
		0x0003: "MsvAvDnsComputerName",	#Contains the fully-qualified domain name (FQDN) of the server.
		0x0004: "MsvAvDnsDomainName",		#Contains the FQDN of the doamin to which the server belongs.
		0x0005: "MsvAvDnsTreeName",			#Contains the DNS tree name (the top-level DNS domain name) of the server's domain.
		0x0007: "MsvAvTimestamp",			#Contains a 64-bit little-endian timestamp representing the time when the server generated the NTLM challenge. Prevents replay attacks.
		0x0009: "MsvAvTargetName",			#Contains the Service Principle Name (SPN) of the target server.
		0x000A: "MsvAvChannelBindings"		#Contains a hash of the channel bindings used in teh authentication process. Ensures integrity of the secure channel (TLS) establishing connection.
	}

	#Handle target information
	def parse_target_info(data):
		index = 0
		target_information = {}
		
		while index < len(data):
			#Unpack the AVID and respective length
			avid, avlen = struct.unpack_from('<HH', data, index)
			#NTLM aligns items on 4-byte boundaries, hence the larger iteration
			index += 4
			
			#Base Case
			if avid == 0x0000:
				break
			
			value = data[index:index + avlen]
			index += avlen
			
			#Decode the value based on AVID
			if avid in [0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0009]:
				value = value.decode('utf-16le')
			elif avid == 0x0007:
				value = struct.unpack_from('<Q', value)[0]
			elif avid == 0x000A:
				value = binascii.hexlify(value).decode('ascii')
				
			target_information[AV_IDS.get(avid, f"Unknown({avid}")] = value
			
		return target_information

	#Extract ASCII characters and bytes from binary message
	signature = binary_message[0:8].decode('ascii')
	message_type = int.from_bytes(binary_message[8:12], 'little')
	
	lm_response_length = struct.unpack('<H', binary_message[12:14])[0]
	lm_response_max_length = struct.unpack('<H', binary_message[14:16])[0]
	lm_response_offset = struct.unpack('<I', binary_message[16:20])[0]
	
	nt_response_length = struct.unpack('<H', binary_message[20:22])[0]
	nt_response_max_length = struct.unpack('<H', binary_message[22:24])[0]
	nt_response_offset = struct.unpack('<I', binary_message[24:28])[0]
	
	domain_length = struct.unpack('<H', binary_message[28:30])[0]
	domain_max_length = struct.unpack('<H', binary_message[30:32])[0]
	domain_offset = struct.unpack('<I', binary_message[32:36])[0]
	
	user_length = struct.unpack('<H', binary_message[36:38])[0]
	user_max_length = struct.unpack('<H', binary_message[38:40])[0]
	user_offset = struct.unpack('<I', binary_message[40:44])[0]
	
	workstation_length = struct.unpack('<H', binary_message[44:46])[0]
	workstation_max_length = struct.unpack('<H', binary_message[46:48])[0]
	workstation_offset = struct.unpack('<I', binary_message[48:52])[0]
	
	encrypted_random_session_key_length = struct.unpack('<H', binary_message[52:54])[0]
	encrypted_random_session_key_max_length = struct.unpack('<H', binary_message[54:56])[0]
	encrypted_random_session_key_offset = struct.unpack('<I', binary_message[56:60])[0]
	
	negotiate_flags = struct.unpack('<I', binary_message[60:64])[0]
	
	#Perform individual length calculations and interpret as UTF-16LE (Little Endian)
	domain = binary_message[domain_offset:domain_offset + domain_length].decode('utf-16le')
	user = binary_message[user_offset:user_offset + user_length].decode('utf-16le')
	workstation = binary_message[workstation_offset:workstation_offset + workstation_length].decode('utf-16le')
	
	#NTLM_FLAGS dictionary
	#TODO: Move this to a more global spot, or at least somewhere less ugly looking
	NTLM_FLAGS = {
		0x00000001: "NEGOTIATE_UNICODE",							#Unicode strings are supported
		0x00000002: "NEGOTIATE_OEM",								#OEM strings are supported
		0x00000004: "REQUEST_TARGET",							#Requests target authentication
		0x00000008: "NEGOTIATE_SIGN",								#Signing of messages is supported
		0x00000010: "NEGOTIATE_SEAL",								#Sealing (encryption) of messages is supported
		0x00000020: "NEGOTIATE_DATAGRAM",						#Datagram authentication
		0x00000040: "NEGOTIATE_LM_KEY",							#LAN Manager key support
		0x00000080: "NEGOTIATE_NETWARE",						#NetWare authentication support
		0x00000100: "NEGOTIATE_NTLM",							#NTLM authentication
		0x00000200: "NEGOTIATE_ANONYMOUS",					#Anonymous authentication
		0x00000400: "NEGOTIATE_OEM_DOMAIN_SUPPLIED",		#OEM domain is supplied
		0x00000800: "NEGOTIATE_OEM_WORKSTATION_SUPPLIED",	#OEM workstation is supplied
		0x00001000: "NEGOTIATE_ALWAYS_SIGN",					#Messages are always signed
		0x00002000: "TARGET_TYPE_DOMAIN",						#Target is a domain
		0x00004000: "TARGET_TYPE_SERVER",						#Target is a server
		0x00008000: "TARGET_TYPE_SHARE",							#Target is a share
		0x00010000: "NEGOTIATE_EXTENDED_SESSIONSECURITY",	#Extended session security
		0x00020000: "NEGOTIATE_IDENTIFY",						#Identify-level authentication
		0x00040000: "REQUEST_NON_NT_SESSION_KEY",			#Requests a non-NT session key
		0x00080000: "NEGOTIATE_TARGET_INFO",					#Target information is supported
		0x00100000: "NEGOTIATE_VERSION",							#Version information supported
		0x00200000: "NEGOTIATE_128",								#128-bit encryption support
		0x00400000: "NEGOTIATE_KEY_EXCHANGE",					#Key exchange support
		0x00800000: "NEGOTIATE_56",								#56-bit encryption support
		0x01000000: "NEGOTIATE_EXPIRY",							#Expiry support
		0x02000000: "NEGOTIATE_LOCK",								#Lock support
		0x04000000: "NEGOTIATE_MANAGED_ACCOUNTS",			#Managed accounts support
		0x08000000: "NEGOTIATE_RESTRICTED",						#Restricted accounts support
		0x10000000: "NEGOTIATE_CHANNEL_BINDINGS",				#Channel bindings support
		0x20000000: "NEGOTIATE_LEGACY",							#Legacy support
		0x40000000: "NEGOTIATE_RESERVED",						#Reserved for future use
		0x80000000: "NEGOTIATE_UNDEFINED",						#Undefined
	}
	
	#Actual flag extraction; use bitwise AND operation to confirm which flags are actually set here
	extracted_flags = [name for flag, name in NTLM_FLAGS.items() if negotiate_flags & flag]
	
	#NTLMv2 Response Extraction
	ntlmv2_response = binary_message[nt_response_offset:nt_response_offset + nt_response_length]
	ntlmv2_byte_count = len(ntlmv2_response) #Byte count to see how the extracted NTLMv2 flag differs from a standard one
	ntlmv2_response_hex = ntlmv2_response.hex()
	
	#Extract the NT response and blob
	response = ntlmv2_response[:16]
	response_hex = response.hex()
	blob = ntlmv2_response[16:]
	blob_hex = blob.hex()
	
	#Unpack blob (juicy target information)
	blob_signature = struct.unpack('<I', blob[:4])[0]
	reserved1 = struct.unpack('<I', blob[4:8])[0]
	timestamp = struct.unpack('<Q', blob[8:16])[0]
	client_nonce = blob[16:24]
	client_nonce_hex = client_nonce.hex()
	#Had many errors with this being empty, so just set to 0 as a default since reserved2 really isn't used for much anyway
	try:
		reserved2 = struct.unpack('<I', blob[24:28])[0]
	except struct.error as e:
		reserved2 = 0
	
	#Extract and store entire target_info section into a single var
	target_info = blob[28:-4]
	
	#Parse through the target info and make a nice little array; utilized the AV_IDs
	parsed_target_info = parse_target_info(target_info)

	#Important Values to Show
	print("\n\n====================================================================")
	print("Important Values: \ndomain =", domain, "\nuser =", user, "\nworkstation= ", workstation)
	print("\nextracted flags: ", extracted_flags)
	print("\nNTLMv2 Response: ", ntlmv2_response.hex(), "(BYTE COUNT ACTUAL =", ntlmv2_byte_count, "--- BYTE COUNT TYPICAL = 24)")
	print("\nNT response: ", response.hex())
	print("\nBlob (hex): ", blob.hex())
	print("\nblob_signature:  ", f"0x{blob_signature:08x}")
	print("reserved1:  ", f"0x{reserved1:08x}")
	print("timestamp:  ", f"0x{timestamp:016x}")
	print("client_nonce:  ", client_nonce.hex())
	print("reserved2:  ", f"0x{reserved2:08x}")
	print()
	for key, value in parsed_target_info.items():
		print(f"{key}: {value}")
	print("====================================================================")
    
	#Return extracted values as dictionary
	return {
        	"signature": signature,
        	"message_type": message_type,
        	"lm_response_length": lm_response_length,
        	"lm_response_max_length": lm_response_max_length,
        	"lm_response_offset": lm_response_offset,
        	"nt_response_length": nt_response_length,
        	"nt_response_max_length": nt_response_max_length,
        	"nt_response_offset": nt_response_offset,
        	"domain_length": domain_length,
        	"domain_max_length": domain_max_length,
        	"domain_offset": domain_offset,
        	"user_length": user_length,
        	"user_max_length": user_max_length,
        	"user_offset": user_offset,
        	"workstation_length": workstation_length,
        	"workstation_max_length": workstation_max_length,
        	"workstation_offset": workstation_offset,
        	"encrypted_random_session_key_length": encrypted_random_session_key_length,
        	"encrypted_random_session_key_max_length": encrypted_random_session_key_max_length,
        	"encrypted_random_session_key_offset": encrypted_random_session_key_offset,
        	"negotiate_flags": negotiate_flags,
        	"domain": domain,
        	"user": user,
        	"workstation": workstation,
        	"client_nonce": client_nonce_hex,
        	"ntlmv2_response": ntlmv2_response_hex,
        	"ntproof": response_hex,
        	"blob": blob_hex,
    	}

#Used to make a nice code snippet; not really needed since I extract this information elsewhere.
#Might remove
def delimit_binary(raw_binary):
	#Filter out bytes to show the printable characters
	characters = ''.join(chr(byte) for byte in raw_binary if 32 <= byte <= 126)
	
	return characters

#ANSI Color Codes; really only used by the banner rn
class colors:
	RED = '\033[91m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	BLUE = '\033[94m'
	MAGENTA = '\033[95m'
	CYAN = '\033[96m'
	WHITE = '\033[97m'
	RESET = '\033[0m'

#Start of Program Execution
print_banner()

#Error checking command-line args
if len(sys.argv) < 2 or len(sys.argv) > 4:
	#Usage Execution Path
	print("Usage (Single-Message Mode): python ./SSPeed.py <base64_message>")
	print("Usage (Multi-Message Mode): python ./SSPeed.py <base64_type_1_message> <base64_type_2_message> <base64_type_3_message>")
	sys.exit(1)
#Multi-Message Mode (2) Execution Path
elif len(sys.argv) > 2:
	print("~~~Multi-Message Mode~~~") 
	
	#Take in args
	b64type1 = sys.argv[1]
	b64type2 = sys.argv[2]
	b64type3 = sys.argv[3]
	
	#Decode to binary for operations
	binary_type1 = base64.b64decode(b64type1)
	binary_type2 = base64.b64decode(b64type2)
	binary_type3 = base64.b64decode(b64type3)
	
	#Parse messages
	parsed_message1 = parse_ntlm_type1_message(2, binary_type1)
	parsed_message2 = parse_ntlm_type2_message(binary_type2)
	parsed_message3 = parse_ntlm_type3_message(binary_type3)
	
	#Output
	#Type 1
	print("\n~~~Parsed Message: \n", parsed_message1)
	
	#Type 2
	print("\n~~~Parsed Message: \n", parsed_message2)
	
	#Type 3
	print("\n~~~Parsed Message: \n", parsed_message3)
	
	#Hash Formatting
	format_hash(parsed_message3['user'], parsed_message3['domain'], parsed_message2['server_nonce'], parsed_message3['ntproof'], parsed_message3['blob'])
	
	#Exit to prevent Single-Message Mode execution path
	sys.exit(1)

#Single-Message Mode (1) Execution Path
base64_message = sys.argv[1]
binary_message = base64.b64decode(base64_message)
delimited_binary_message = delimit_binary(binary_message)

#Initial parse call will determine the message type and automatically reassign to appropriate function path
parsed_message = parse_ntlm_type1_message(1, binary_message)

# Parse the message based on its type
if parsed_message['message_type'] == 1:
    	parsed_message = parse_ntlm_type1_message(1, binary_message)
elif parsed_message['message_type'] == 2:
    	parsed_message = parse_ntlm_type2_message(binary_message)
elif parsed_message['message_type'] == 3:
    	parsed_message = parse_ntlm_type3_message(binary_message)
else:
    	print("Unknown NTLM message type.")
    	sys.exit(1)

#End Output
print("\n~~~Parsed Message: \n", parsed_message)
print("\n~~~Raw Binary:\n", binary_message)
print("\n~~~Delimited Binary:\n", delimited_binary_message)
print("\n~~~Raw Binary (hex):\n", binary_message.hex())
