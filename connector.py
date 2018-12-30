import os
import socket
import time
import struct
import utils

class Connector:

    PEER_SEED_URL = 'seed.bitcoinabc.org'
    HEADER_LENGTH = 24
    VERSION = 180002
    MAGIC_MAIN_BCH=0xe8f3e1e3

    def __init__(self):
        self.watchdog()

    def watchdog(self):
        #	rawData = requests.get(url='https://api.blockchair.com/bitcoin-cash/nodes').json()
        #	peers = [x.split(':')[0] for x in rawData['data']['nodes'].keys()]
        peers = socket.gethostbyname_ex(Connector.PEER_SEED_URL)[2]
        for peer in peers:
            try:
                print peer
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((peer, 8333))
                self.sock = sock
                self.sendVersionMsg()
                self.recvMsg()
                break
            except Exception as e:
                print e
                continue
        self.recvMsg()
        self.sendVerackMsg()

    def sendVersionMsg(self):
        version = Connector.VERSION
        services = 1
        timestamp = int(time.time())
        addrRecv = b'\x00'*26
        addrFrom = b'\x00'*26
        nonce = struct.unpack('<Q', os.urandom(8))[0]
        userAgent = utils.varstr('')
        startHeight = 0
        payload = struct.pack('<LQQ26s26sQsL', version, services, timestamp, addrRecv, addrFrom, nonce, userAgent, startHeight)
        self.sock.send(Connector.createMsg('version', payload))

    def sendVerackMsg(self):
        self.sock.send(Connector.createMsg('verack', ''))

    def sendTrxMsg(self, transaction):
	    self.sock.send(Connector.createMsg('tx', transaction))

    def recvMsg(self):
        # get header
        header = Connector.sockRead(self.sock, Connector.HEADER_LENGTH)
        _, command, payloadLen, _ = struct.unpack('<L12sL4s', header)
        # get payload
        payload = Connector.sockRead(self.sock, payloadLen)
        return command, payload

    @staticmethod
    def sockRead(sock, count):
        data = b''
        while len(data) < count:
            data += sock.recv(count - len(data))
        return data

    @staticmethod
    def createMsg(command, payload):
	    checksum = utils.doubleSHA256(payload)[0:4]
	    return struct.pack('I12sI4s', Connector.MAGIC_MAIN_BCH, command, len(payload), checksum) + payload