import binascii
import struct
import ecdsa
import utils
import requests
import logging

'''
Only one input - several outputs transaction is supported
'''
class TxIn:

    def __init__(self, prevTrxHash, prevOutputIdx, inputAmount):
        self.inputAmount = inputAmount
        self.prevOutputHash = binascii.unhexlify(prevTrxHash)[::-1]
        self.prevOutputIdx = prevOutputIdx

class Transaction:

    TRX_VERSION = 1
    INPUTS_LENGTH = b'\x01'
    SEQUENCE = b'\xff\xff\xff\xff'
    LOCK_TIME = b'\x00\x00\x00\x00'
    SIGHASH_TYPE = b'\x41\x00\x00\x00'
    SIGHASH_ALL_FORKID = b'\x41'

    def __init__(self, inputs, initialBalance, privateKey, senderAddress, receiverAddress, amount, fee):
        self.inputs = inputs
        self.privateKey = privateKey
        self.scriptPubKey = utils.addressToScriptPubKey(senderAddress)
        self.outputs = [(utils.addressToScriptPubKey(receiverAddress), amount), \
            (utils.addressToScriptPubKey(senderAddress), initialBalance - amount - fee)]

    def buildSignedTransaction(self):
        noName = utils.doubleSHA256(''.join([
                    txIn.prevOutputHash + struct.pack('<L', txIn.prevOutputIdx)
                    for txIn in self.inputs
                ]))
        noName += utils.doubleSHA256(''.join([
            Transaction.SEQUENCE
            for txIn in self.inputs
        ]))
        for input in self.inputs:
            signatureBodyHash = utils.doubleSHA256(Transaction.getSignatureBody(noName, input.prevOutputHash, input.prevOutputIdx, input.inputAmount, self.scriptPubKey, self.outputs))
            #create a public/private key pair out of the provided private key
            pk = utils.privateKeyToCompressedPublicKey(self.privateKey)
            sk = ecdsa.SigningKey.from_string(self.privateKey, curve=ecdsa.SECP256k1)
            vk = ecdsa.VerifyingKey.from_string(utils.privateKeyToPublicKey(self.privateKey)[1:], curve=ecdsa.SECP256k1)
            #sign the hash from step with the secret key
            trxSignature = utils.sign(sk, signatureBodyHash)
            #check signature
            vk.verify_digest(utils.derSigToHexSig(trxSignature), signatureBodyHash)
            input.scriptSig = utils.varstr(trxSignature + Transaction.SIGHASH_ALL_FORKID) + utils.varstr(pk)
            
        signedTrx = Transaction.getRawTransaction(self.inputs, self.outputs)
        return signedTrx

    @staticmethod
    def formatOutput(output):
        scriptPubKey, value = output
        return struct.pack('<Q', value) + utils.varstr(scriptPubKey)

    @staticmethod
    def formatInput(input):
        return  ( input.prevOutputHash 
                + struct.pack('<L', input.prevOutputIdx)
                + utils.varstr(input.scriptSig)
                + Transaction.SEQUENCE
                )
    
    @staticmethod
    def getSignatureBody(notName, prevOutputHash, prevOutputIdx, inputAmount, scriptPubKey, outputs):
        return  ( struct.pack('<L', Transaction.TRX_VERSION)
                + notName
                + prevOutputHash + struct.pack('<L', prevOutputIdx)
                + utils.varstr(scriptPubKey)
                + struct.pack('<Q', inputAmount)
                + Transaction.SEQUENCE
                + utils.doubleSHA256(b''.join(map(Transaction.formatOutput, outputs))) 
                + Transaction.LOCK_TIME
                + Transaction.SIGHASH_TYPE
                )

    @staticmethod
    def getRawTransaction(inputs, outputs):
        return  ( struct.pack('<L', Transaction.TRX_VERSION)
                + struct.pack('B', len(inputs))
                + b''.join(map(Transaction.formatInput, inputs))
                + struct.pack('B', len(outputs))
                + b''.join(map(Transaction.formatOutput, outputs))
                + Transaction.LOCK_TIME
                )