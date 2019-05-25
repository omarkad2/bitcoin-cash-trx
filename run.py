from flask import Flask, render_template, request
from transaction import Transaction 
from connector import Connector
from threading import Thread
import binascii
import utils
import logging
import time


logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
	connector = Connector()
	Thread(target = connector.listen).start()
	prevOutputHash = None
	prevOutputIdx = 0
	inputAmount = 0
	outputAmount = 0
	wif = None
	senderAddr = None
	receiverAddr = None
	if request.method == 'POST' and 'wif' in request.form and 'senderAddr' in request.form and 'receiverAddr' in request.form:
		wif = str(request.form['wif'].strip())
		outputAmount = float(request.form['outputAmount'].strip())
		senderAddr = str(request.form['senderAddr'].strip())
		receiverAddr = str(request.form['receiverAddr'].strip())
		transaction = Transaction(wif, senderAddr, receiverAddr, utils.convertBCHtoSatoshis(outputAmount))
		signedTrx = transaction.buildSignedTransaction()
		connector.sendTrxMsg(signedTrx)
		return render_template('result.html', txid=binascii.hexlify(utils.doubleSHA256(signedTrx)[::-1]))

	return render_template('index.html')

if __name__ == '__main__':
	app.run("0.0.0.0")
