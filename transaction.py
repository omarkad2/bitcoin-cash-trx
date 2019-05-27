import binascii
import struct
import ecdsa
import utils

class TxIn:

    def __init__(self, prevTrxHash, prevOutputIdx, inputAmount):
        self.inputAmount = inputAmount
        self.prevOutputHash = binascii.unhexlify(prevTrxHash)[::-1]
        self.prevOutputIdx = prevOutputIdx

    def serialize(self):
        return  ( self.prevOutputHash 
                + struct.pack('<L', self.prevOutputIdx)
                + utils.varstr(self.scriptSig)
                + Transaction.SEQUENCE
                )

class TxOut:

    def __init__(self, scriptPubKey, value):
        self.scriptPubKey = scriptPubKey
        self.value = value

    def serialize(self):
        return struct.pack('<Q', self.value) + utils.varstr(self.scriptPubKey)

class Transaction:

    TRX_VERSION = 1
    SEQUENCE = b'\xff\xff\xff\xff'
    LOCK_TIME = b'\x00\x00\x00\x00'
    SIGHASH_TYPE = b'\x41\x00\x00\x00'
    SIGHASH_ALL_FORKID = b'\x41'

    def __init__(self, privateKey, senderAddress, inputs, outputs):
        self.privateKey = privateKey
        self.scriptPubKey = utils.addressToScriptPubKey(senderAddress)
        self.inputs = inputs
        self.outputs = outputs

    def buildSignedTransaction(self):
        commonHash = utils.doubleSHA256(''.join([
                    txIn.prevOutputHash + struct.pack('<L', txIn.prevOutputIdx)
                    for txIn in self.inputs
                ]))
        commonHash += utils.doubleSHA256(''.join([
            Transaction.SEQUENCE
            for txIn in self.inputs
        ]))
        for input in self.inputs:
            signatureBodyHash = utils.doubleSHA256(Transaction.getInputSignatureBody(commonHash, input.prevOutputHash, input.prevOutputIdx, input.inputAmount, self.scriptPubKey, self.outputs))
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
    def getInputSignatureBody(commonHash, prevOutputHash, prevOutputIdx, inputAmount, scriptPubKey, outputs):
        return  ( struct.pack('<L', Transaction.TRX_VERSION)
                + commonHash
                + prevOutputHash + struct.pack('<L', prevOutputIdx)
                + utils.varstr(scriptPubKey)
                + struct.pack('<Q', inputAmount)
                + Transaction.SEQUENCE
                + utils.doubleSHA256(b''.join(map(TxOut.serialize, outputs))) 
                + Transaction.LOCK_TIME
                + Transaction.SIGHASH_TYPE
                )

    @staticmethod
    def getRawTransaction(inputs, outputs):
        return  ( struct.pack('<L', Transaction.TRX_VERSION)
                + struct.pack('B', len(inputs))
                + b''.join(map(TxIn.serialize, inputs))
                + struct.pack('B', len(outputs))
                + b''.join(map(TxOut.serialize, outputs))
                + Transaction.LOCK_TIME
                )