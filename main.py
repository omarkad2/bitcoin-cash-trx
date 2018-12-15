#!/usr/bin/env python

import os
import binascii
import ecdsa
from baseconv import base58
import hashlib

def base58(address_hex):
	alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
	b58_string = ''
	# Get the number of leading zeros and convert hex to decimal
	leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
	# Convert hex to decimal
	address_int = int(address_hex, 16)
	# Append digits to the start of string
	while address_int > 0:
		digit = address_int % 58
		digit_char = alphabet[digit]
		b58_string = digit_char + b58_string
		address_int //= 58
	# Add '1' for each 2 leading zeros
	ones = leading_zeros // 2
	for one in range(ones):
		b58_string = '1' + b58_string
	return b58_string

def privateKey256():
	# 256-bit private key
	return os.urandom(32)

def privateKeyToWif(secretKeyBytes):    
	return utils.base58CheckEncode(0x80, secretKeyBytes)
    
def privateKeyToPublicKey(secretKeyBytes):
	key = ecdsa.SigningKey.from_string(secretKeyBytes, curve=ecdsa.SECP256k1).verifying_key
	keyBytes = key.to_string()
	# 512-bit public key with prefix '04'
	return '\04' + keyBytes 
    
def pubKeyToAddr(publicKeyBytes):
	# 160-bit Hashed public key & Add the netwok byte 0x00 for main network
	# 0x6f for test network
	ripemd160 = hashlib.new('ripemd160')
	ripemd160.update(hashlib.sha256(publicKeyBytes).digest())
	hashedPublicKey = '\00' + ripemd160.digest()
	# Calculating the checksum with double SHA-256 (take 4 first bytes of the result)
	doubleSHA256Hash = hashlib.sha256(hashlib.sha256(hashedPublicKey).digest()).digest()	
	checksum = doubleSHA256Hash[:4]
	# Address = Base58(HashedPublicKey + checksum)
	addressHex = binascii.hexlify(hashedPublicKey + checksum)
	return base58(addressHex)

privateKey = privateKey256()
publicKey = privateKeyToPublicKey(privateKey)
print binascii.hexlify(privateKey)
print binascii.hexlify(publicKey)
#print privateKeyToWif(private_key)
print pubKeyToAddr(publicKey)

