#!/usr/bin/env python

import os
import binascii
import ecdsa
import hashlib
import struct
import base58

################################# KEY / ADDRESS GENERATION ###################################
# https://en.bitcoin.it/wiki/Base58Check_encoding

def doubleSHA256(data):
	return hashlib.sha256(hashlib.sha256(data).digest()).digest()

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
	return base58CheckEncoding('\x80', secretKeyBytes)

def wifToPrivateKey(wifPrivateKey):
	return base58CheckDecoding(wifPrivateKey) 
	    
def privateKeyToPublicKey(secretKeyBytes):
	key = ecdsa.SigningKey.from_string(secretKeyBytes, curve=ecdsa.SECP256k1).verifying_key
	keyBytes = key.to_string()
	# 512-bit public key with prefix '04'
	return '\x04' + keyBytes 
    
def pubKeyToAddr(publicKeyBytes):
	# 160-bit Hashed public key & Add the netwok byte 0x00 for main network
	# 0x6f for test network
	ripemd160 = hashlib.new('ripemd160')
	ripemd160.update(hashlib.sha256(publicKeyBytes).digest())
	return base58CheckEncoding('\x00', ripemd160.digest())

def addressToScriptPubKey(address):
	# 76 A9 14 (20 bytes) 88AC
	return '76a914' + binascii.hexlify(base58CheckDecoding(address)) + '88ac'	

privateKey = privateKey256()
publicKey = privateKeyToPublicKey(privateKey)
wifPrivateKey = privateKeyToWif(privateKey)
address = pubKeyToAddr(publicKey)
print binascii.hexlify(privateKey)
print binascii.hexlify(publicKey)
print wifPrivateKey
print address

print binascii.hexlify(wifToPrivateKey(wifPrivateKey))
################################# TRANSACTION GENERATION ###################################
# For a waklthrough check the answer in this thread : https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
HEX_PREVIOUS_TRX = 'a561cf6e8d347f5e441daafcb688d70d7b332d5601d243a503bdba4345e78276'
RECEIVER_ADDR = '15QCoirrat6PRNunChbnyuKMXvDnjBrgP5'
AMOUNT_TO_SEND = 0.00000101
AMOUNT_TO_KEEP = 0.68801

def convertBCHtoSatoshi(bch):
	return bch * 2503154

def formatOutput(output):
	scriptPubKey, value = output
	return (binascii.hexlify(struct.pack('<Q', value))
		+ '%02x' % len(scriptPubKey.decode('hex'))
		+ scriptPubKey)

def generateRawTransaction(prevOutputHash, prevOutputIdx, scriptSig, outputs):
	return  ( '01000000' 
			+ '01'
			+ binascii.hexlify(prevOutputHash.decode('hex')[::-1])
			+ binascii.hexlify(struct.pack('<L', prevOutputIdx))
			+ '%02x' % len(scriptSig)
			+ scriptSig
			+ 'ffffffff'
			+ '%02x' % len(outputs)
			+ ''.join(map(formatOutput, outputs)) 
			+ '00000000'
			)
def generateSignedTransaction(privateKey, prevOutputHash, prevOutputIdx, scriptPubKey, outputs):
	trxToSign = generateRawTransaction(prevOutputHash, prevOutputIdx, scriptPubKey, outputs) + '01000000'
	hashTrxToSign = doubleSHA256(trxToSign)
	#create a public/private key pair out of the provided private key
	sk = ecdsa.SigningKey.from_string(privateKey, curve=ecdsa.SECP256k1)
	pk = privateKeyToPublicKey(sk.to_string())
	#sign the hash from step with the secret key
	trxSignature = sk.sign_digest(hashTrxToSign, sigencode=ecdsa.util.sigencode_der)
	#to this signature we append the one-byte hash code type '01'
	trxSignature = trxSignature + '01'
	'''
	Construct the final scriptSig by concatenating : 
	- One-byte script OPCODE containing the length of the DER-encoded signature plus 1 (the length of the one-byte hash code type)
	- The actual DER-encoded signature plus the one-byte hash code type
	- One-byte script OPCODE containing the length of the public key
	- The actual public key
	'''
	scriptSig = binascii.hexlify(chr(len(trxSignature)) + trxSignature) + binascii.hexlify(chr(len(pk)) + pk)
	print scriptSig
	signedTrx = generateRawTransaction(prevOutputHash, prevOutputIdx, scriptSig, outputs)
	return signedTrx

def makeTransaction(WIFPrivateKey, prevTrxHash, prevOutputIdx, senderPublicKey, receivers):
	#convert WIF to private key
	privateKey = wifToPrivateKey(WIFPrivateKey)
	signedTrx = generateSignedTransaction(privateKey, prevTrxHash, prevOutputIdx, senderPublicKey, receivers)
	print 'Signed Transaction : ' + signedTrx

outputs = [(addressToScriptPubKey(RECEIVER_ADDR), convertBCHtoSatoshi(AMOUNT_TO_SEND)), (addressToScriptPubKey(address), convertBCHtoSatoshi(AMOUNT_TO_KEEP))]
makeTransaction(wifPrivateKey, HEX_PREVIOUS_TRX, 0, addressToScriptPubKey(address), outputs)

