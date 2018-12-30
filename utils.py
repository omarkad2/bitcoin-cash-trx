import os
import binascii
import ecdsa
import hashlib
import struct
import base58
import unittest

# Variable length Integer
def varint(intData):
	if intData < 0xfd:
		return struct.pack('<B', intData)
	elif intData < 0xffff:
		return struct.pack('<cH', '\xfd', intData)
	elif intData < 0xffffffff:
		return struct.pack('<cL', '\xfe', intData)
	else:
		return struct.pack('<cQ', '\xff', intData)

# Variable length String
def varstr(strData):
	return varint(len(strData)) + strData

def doubleSHA256(data):
	return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# https://en.bitcoin.it/wiki/Base58Check_encoding
def base58CheckEncoding(version, payload):
	keyBytes = version + payload
	# Calculating the checksum with double SHA-256 (take 4 first bytes of the result)
	doubleSHA256Hash = doubleSHA256(keyBytes)
	# Address = Base58(HashedPublicKey + checksum)
	checksum = doubleSHA256Hash[:4]
	return base58.b58encode(keyBytes + checksum)

def base58CheckDecoding(payload):
	result = base58.b58decode(payload)[0:-4]
	return result[1:]
 
def privateKey256():
	# 256-bit private key
	return os.urandom(32)

def privateKeyToWif(secretKeyBytes):    
	return base58CheckEncoding('\x80', secretKeyBytes + '\x01')  

def wifToPrivateKey(wifPrivateKey):
	return base58CheckDecoding(wifPrivateKey)[:-1] 
	    
def privateKeyToPublicKey(secretKeyBytes):
	key = ecdsa.SigningKey.from_string(secretKeyBytes, curve=ecdsa.SECP256k1).verifying_key
	keyBytes = key.to_string()
	# 512-bit public key with prefix '04'
	return '\x04' + keyBytes 

def privateKeyToCompressedPublicKey(secretKeyBytes):
	key = ecdsa.SigningKey.from_string(secretKeyBytes, curve=ecdsa.SECP256k1).verifying_key
	keyBytes = key.to_string()
	keyHex = binascii.hexlify(keyBytes)
	keyStr = keyHex.decode('utf-8')
	halfLen = len(keyHex) // 2
	keyHalf = keyHex[:halfLen]
	# Add bitcoin byte: 0x02 if the last digit is even, 0x03 if the last digit is odd
	lastByte = int(keyStr[-1], 16)
	bitcoinByte = '\x02' if lastByte % 2 == 0 else b'\x03'
	publicKey = bitcoinByte + binascii.unhexlify(keyHalf)
	return publicKey
	 
def pubKeyToAddr(publicKeyBytes):
	# 160-bit Hashed public key & Add the netwok byte 0x00 for main network
	# 0x6f for test network
	ripemd160 = hashlib.new('ripemd160')
	ripemd160.update(hashlib.sha256(publicKeyBytes).digest())
	return base58CheckEncoding('\x00', ripemd160.digest())

def addressToScriptPubKey(address):
	# OP_DUP OP_HASH160 (20 bytes) OP_EQUALVERIFY OP_CHECKSIG
	# 76 A9 14 (20 bytes) 88AC
	return b'\x76\xa9\x14' + base58CheckDecoding(address) + b'\x88\xac'

def convertBCHtoSatoshis(bch):
	return bch * 10**8

def sign(secretKey, data):
	while 1:
		sig = secretKey.sign_digest(data, sigencode=ecdsa.util.sigencode_der)
		N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
		_, s = ecdsa.util.sigdecode_der(sig, secretKey.curve.generator.order())
		if s < N/2:
			break
	return sig

def derSigToHexSig(s):
	s, junk = ecdsa.der.remove_sequence(s)
	assert(junk == b'')
	x, s = ecdsa.der.remove_integer(s)
	y, s = ecdsa.der.remove_integer(s)
	return binascii.unhexlify(('%064x%064x' % (x, y)))