import os
import socket
import time
import struct
import utils
import logging
import binascii

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
                logging.info(peer)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # sock.settimeout(5.0)
                sock.connect((peer, 8333))
                self.sock = sock
                self.sendVersionMsg()
                cmd, payload = self.recvMsg()
                Connector.displayMsg(cmd, payload)
                break
            except Exception as e:
                logging.error(e)
                continue
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
        cmd, payload = self.recvMsg()
        Connector.displayMsg(cmd, payload)

    def recvMsg(self):
        # get header
        header = Connector.sockRead(self.sock, Connector.HEADER_LENGTH)
        _, command, payloadLen, _ = struct.unpack('<L12sL4s', header)
        # get payload
        payload = Connector.sockRead(self.sock, payloadLen)
        return command, payload

    def listen(self):
        while 1:
            cmd, payload = self.recvMsg()
            Connector.displayMsg(cmd, payload)

    @staticmethod
    def displayMsg(cmd, payload):
        cmd = cmd.replace('\0', '') # Remove null termination
        logging.debug("--- {} ---".format(cmd))
        if cmd == 'version':
            version, services, timestamp, addr_recv, addr_from, nonce = struct.unpack('<LQQ26s26sQ', payload[:80])
            agent, agent_len = utils.processVarStr(payload[80:])

            start_height = struct.unpack('<L', payload[80 + agent_len:84 + agent_len])[0]
            logging.debug('%d %x %x %s %s %x %s %x' % (
                version, services, timestamp, utils.processAddr(addr_recv), utils.processAddr(addr_from),
                nonce, agent, start_height))
        elif cmd == 'inv' or cmd == 'getdata':
            count, offset = utils.processVarInt(payload)
            for i in range(0, count):
                type, hash = struct.unpack('<L32s', payload[offset:offset+36])
                # Note: hash is reversed
                logging.debug("{} {}".format(type, hash[::-1].encode('hex')))
                if type == 2:
                    break
                offset += 36
        elif cmd == 'addr':
            count, offset = utils.processVarInt(payload)
            for i in range(0, count):
                timestamp, = struct.unpack('<L', payload[offset:offset+4])
                addr = utils.processAddr(payload[offset+4:offset+30])
                offset += 30
                logging.debug("{} -> {}".format(time.ctime(timestamp), addr))
        elif cmd == 'getheaders':
            version, = struct.unpack('<I', payload[:4])
            logging.debug("{}".format(version))
            count, offset = utils.processVarInt(payload[4:-32])
            for i in range(0, count):
                blockLocator, = struct.unpack('<32s', payload[offset:offset+32])
                logging.debug("{}".format(blockLocator[::-1].encode('hex')))
                offset += 32
            hashStop, = struct.unpack('<32s', payload[-32:])
            logging.debug("{}".format(hashStop.encode('hex')))
        elif cmd == 'feefilter':
            minFee, = struct.unpack('<q', payload)
            logging.debug("minimal fee per kB {}".format(minFee))
        elif cmd == 'reject':
            logging.debug(':'.join(x.encode('hex') for x in payload))
        else:
            logging.debug(':'.join(x.encode('hex') for x in payload))
        logging.debug('---\n')

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