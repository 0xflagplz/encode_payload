#!/usr/bin/python

import argparse
from Crypto.Hash import MD5
from Crypto.Cipher import AES
import pyscrypt
from base64 import b64encode
from os import urandom
import os


# Crypto Functions
#------------------------------------------------------------------------
def xor(data, key):
	l = len(key)
	keyAsInt = map(ord, key)
	return bytes(bytearray((
	    (data[i] ^ keyAsInt[i % l]) for i in range(0,len(data))
	)))

#------------------------------------------------------------------------

def pad(s):
	"""PKCS7 padding"""
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

#------------------------------------------------------------------------
def aesEncrypt(clearText, key):
	"""Encrypts data with the provided key.
	The returned byte array is as follow:
	:==============:==================================================:
	: IV (16bytes) :    Encrypted (data + PKCS7 padding information)  :
	:==============:==================================================:
	"""

	# Generate a crypto secure random Initialization Vector
	iv = urandom(AES.block_size)

	# Perform PKCS7 padding so that clearText is a multiple of the block size
	clearText = pad(clearText)

	cipher = AES.new(key, AES.MODE_CBC, iv)
	return iv + cipher.encrypt(bytes(clearText))

# Output Formating

def formatCPP(data, key, cipherType):
	shellcode = "\\x"
	shellcode += "\\x".join(format(ord(b),'02x') for b in data)
	print 'char encryptedShellcode[] = "' + shellcode +'";'

	print 'char key[] = "' + key +'";'

	print 'char cipherType[] = "' + cipherType + '";'
	

def formatB64(data):
	return b64encode(data)



# Main Function

if __name__ == '__main__':
	# Parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("shellcodeFile", help="File name containing the raw shellcode to be encoded/encrypted")
        parser.add_argument("key", help="Key used to transform (XOR or AES encryption) the shellcode")
	args = parser.parse_args() 

	# Open shellcode file and read all bytes from it
	try:
		with open(args.shellcodeFile) as shellcodeFileHandle:
			shellcodeBytes = bytearray(shellcodeFileHandle.read())
			shellcodeFileHandle.close()
			print("[*] Shellcode file [{}] successfully loaded".format(args.shellcodeFile))
	except IOError:
		print("[!] Could not open or read file [{}]".format(args.shellcodeFile))
		quit()

	print("[*] MD5 hash of the initial shellcode: [{}]".format(MD5.new(shellcodeBytes).hexdigest()))
	print("[*] Original Shellcode size: [{}] bytes".format(len(shellcodeBytes)))


	# Display formated output
	
	print("\n\n[*] Add the following to C++ code file")
	print "\n==================================== XOR C++ Code ====================================\n"
	masterKey = args.key
	print("[*] XOR encoding the shellcode with key [{}]".format(masterKey))
	transformedShellcode = xor(shellcodeBytes, masterKey)
	cipherType = 'xor'
	formatCPP(transformedShellcode, masterKey, cipherType)

	print("\n[*] Encrypted XOR shellcode size: [{}] bytes".format(len(transformedShellcode)))
		
	print "\n==================================== AES C++ Code ====================================\n"
	key = pyscrypt.hash(args.key, "saltmegood", 1024, 1, 1, 16)
	masterKey = formatB64(key)
	print("[*] AES encrypting the shellcode with 128 bits derived key [{}]".format(masterKey))
	transformedShellcode = aesEncrypt(shellcodeBytes, key)
	cipherType = 'aes'
	formatCPP(transformedShellcode, masterKey, cipherType)

	print("\n[*] Encrypted AES shellcode size: [{}] bytes".format(len(transformedShellcode)))

	print "\n\n================================= C++ Decrypt Code =================================\n"
	print "int j = 0;\n"
	print "for (int i = 0; i < sizeof encryptedShellcode; i++) {	\n"
	print "     if (j == sizeof key - 1) j = 0;	\n"
	print "     shellcode[i] = encryptedShellcode[i] ^ key[j];	\n"   
	print "     j++;	\n" 
	print "}\n"

	print("\n============================= here is the Base64 string bc why not =============================\n")		
	print formatB64(transformedShellcode)
	print ""
