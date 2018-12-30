import binascii
import struct
import ecdsa
import utils

'''
Only one input - several outputs transaction is supported
'''
class Transaction:

    TRX_VERSION = 1
    INPUTS_LENGTH = b'\x01'
    SEQUENCE = b'\xff\xff\xff\xff'
    LOCK_TIME = b'\x00\x00\x00\x00'
    SIGHASH_TYPE = b'\x41\x00\x00\x00'
    SIGHASH_ALL_FORKID = b'\x41'

    def __init__(self, prevOutputHash, prevOutputIdx, wifPrivateKey, inputAmount, scriptPubKey, outputs):
        self.trxId = binascii.unhexlify(prevOutputHash)[::-1]
        self.prevOutputIdx = prevOutputIdx
        self.wifPrivateKey = wifPrivateKey
        self.privateKey = utils.wifToPrivateKey(wifPrivateKey)
        self.inputAmount = inputAmount
        self.scriptPubKey = binascii.unhexlify(scriptPubKey)
        self.outputs = outputs

    def buildSignedTransaction(self):
        signatureBodyHash = utils.doubleSHA256(Transaction.getSignatureBody(self.trxId, self.prevOutputIdx, self.inputAmount, self.scriptPubKey, self.outputs))
        #create a public/private key pair out of the provided private key
        pk = utils.privateKeyToCompressedPublicKey(self.privateKey)
        sk = ecdsa.SigningKey.from_string(self.privateKey, curve=ecdsa.SECP256k1)
        vk = ecdsa.VerifyingKey.from_string(utils.privateKeyToPublicKey(self.privateKey)[1:], curve=ecdsa.SECP256k1)
        #sign the hash from step with the secret key
        trxSignature = utils.sign(sk, signatureBodyHash)
        #check signature
        vk.verify_digest(utils.derSigToHexSig(trxSignature), signatureBodyHash)
        scriptSig = utils.varstr(trxSignature + Transaction.SIGHASH_ALL_FORKID) + utils.varstr(pk)
        signedTrx = Transaction.getRawTransaction(self.trxId, self.prevOutputIdx, scriptSig, self.outputs)
        return signedTrx

    @staticmethod
    def formatOutput(output):
        scriptPubKey, value = output
        return struct.pack('<Q', value) + utils.varstr(scriptPubKey)
    
    @staticmethod
    def getSignatureBody(prevOutputHash, prevOutputIdx, inputAmount, scriptPubKey, outputs):
        return  ( struct.pack('<L', Transaction.TRX_VERSION) 
                + utils.doubleSHA256(prevOutputHash + struct.pack('<L', prevOutputIdx))
                + utils.doubleSHA256(Transaction.SEQUENCE)
                + prevOutputHash + struct.pack('<L', prevOutputIdx)
                + utils.varstr(scriptPubKey)
                + struct.pack('<Q', utils.convertBCHtoSatoshis(inputAmount))
                + Transaction.SEQUENCE
                + utils.doubleSHA256(b''.join(map(Transaction.formatOutput, outputs))) 
                + Transaction.LOCK_TIME
                + Transaction.SIGHASH_TYPE
			    )

    @staticmethod
    def getRawTransaction(prevOutputHash, prevOutputIdx, scriptSig, outputs):
        return  ( struct.pack('<L', Transaction.TRX_VERSION)
                + Transaction.INPUTS_LENGTH
                + prevOutputHash + struct.pack('<L', prevOutputIdx)
                + utils.varstr(scriptSig)
                + Transaction.SEQUENCE
                + struct.pack('B', len(outputs))
                + b''.join(map(Transaction.formatOutput, outputs))
                + Transaction.LOCK_TIME
                )