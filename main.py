#!/usr/bin/env python

import os
import binascii
import ecdsa
import hashlib
import struct
import base58
import time
import socket
from hexdump import hexdump
import requests

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
	# OP_DUP OP_HASH160 (20 bytes) OP_EQUALVERIFY OP_CHECKSIG
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
SENDER_ADDR = '1kRZNesgFstmSvWKHWeHqbaRZ2bCb8mtb'
AMOUNT_TO_SEND = 0.0000565
AMOUNT_TO_KEEP = 0.68789802

def convertBCHtoSatoshi(bch):
	return bch * 10**8

def formatOutput(output):
	scriptPubKey, value = output
	return (binascii.hexlify(struct.pack('<Q', value))
		+ '%02x' % len(scriptPubKey.decode('hex'))
		+ scriptPubKey)

def generateRawTransaction(prevOutputHash, prevOutputIdx, scriptSig, outputs):
	return  ( '02000000' 
			+ '01'
			+ binascii.hexlify(prevOutputHash.decode('hex')[::-1])
			+ binascii.hexlify(struct.pack('<L', prevOutputIdx))
			+ '%02x' % len(scriptSig.decode('hex'))
			+ scriptSig
			+ 'ffffffff'
			+ '%02x' % len(outputs)
			+ ''.join(map(formatOutput, outputs)) 
			+ '00000000'
			)
def generateSignedTransaction(privateKey, prevOutputHash, prevOutputIdx, scriptPubKey, outputs):
	trxToSign = generateRawTransaction(prevOutputHash, prevOutputIdx, scriptPubKey, outputs) + '01000000'
	print '\n' + trxToSign + '\n'
	hashTrxToSign = doubleSHA256(trxToSign)
	#create a public/private key pair out of the provided private key
	sk = ecdsa.SigningKey.from_string(privateKey, curve=ecdsa.SECP256k1)
	#sign the hash from step with the secret key
	trxSignature = sk.sign_digest(hashTrxToSign, sigencode=ecdsa.util.sigencode_der) + '\01'
	pk = publicKey #privateKeyToPublicKey(privateKey)
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

################################# SEND TRANSACTION FOR MINING  ###################################
# https://en.bitcoin.it/wiki/Protocol_documentation
#4 	magic 		uint32_t 	Magic value indicating message origin network, and used to seek to next message when stream state is unknown
#12 command 	char[12] 	ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
#4 	length 		uint32_t 	Length of payload in number of bytes
#4 	checksum 	uint32_t 	First 4 bytes of sha256(sha256(payload))
#? 	payload 	uchar[] 	The actual data 
MAGIC_MAIN=0xD9B4BEF9
MAGIC_TEST_NET=0xDAB5BFFA
MAGIC_TEST_NET3=0x0709110B
BUFFER_SIZE=4096
MAGIC_BCH=0xe8f3e1e3

def sockRead(sock, count):
	data = b''
	while len(data) < count:
		data += sock.recv(count - len(data))
	return data

def recvMsg(sock):
	magic, command, payloadLen, checksum = struct.unpack('<L12sL4s', sockRead(sock, 24))
	payload = sockRead(sock, payloadLen)
	print command
	hexdump(payload)
	return command, payload
	
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

def netaddr(ipaddr, port, timestamp=True):
	services = 1
	return (struct.pack('<Q12s', services, '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff') +
struct.pack('>4sH', ipaddr, port))

def createMsg(command, payload):
	checksum = doubleSHA256(payload)[0:4]
	return struct.pack('L12sL4s', MAGIC_BCH, command, len(payload), checksum) + payload

def createVersionMsg():
	version = 180002
	services = 1
	timestamp = int(time.time())
	addrRecv = netaddr(socket.inet_aton('127.0.0.1'), 8333, False)
	addrFrom = netaddr(socket.inet_aton('127.0.0.1'), 8333, False)
	nonce = struct.unpack('<Q', os.urandom(8))[0]
	userAgent = varstr('')
	startHeight = 0
	payload = struct.pack('<LQQ26s26sQsL', version, services, timestamp, addrRecv, addrFrom, nonce, userAgent, startHeight)
	return createMsg('version', payload)

def createTrxMsg(trxHex):
	return createMsg('tx', trxHex)

if __name__ == '__main__':
	# Get peers
	rawData = requests.get(url='https://api.blockchair.com/bitcoin-cash/nodes').json()
	peers = [x.split(':')[0] for x in rawData['data']['nodes'].keys()]
	for peer in peers:
		try:
			print 'Sending message to : %s' % peer
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(5)
			sock.connect((peer, 8333))
			sock.send(createVersionMsg())
			command, payload = recvMsg(sock)
			print 'Commande: %s - Payload: %d -> %s' % (command, len(payload), binascii.hexlify(payload))
			break
		except :
			continue
