from flask import Flask, render_template, request
from transaction import Transaction 
from connector import Connector
import binascii
import utils

app = Flask(__name__)

FEE = 100

@app.route('/', methods=['GET', 'POST'])
def index():
	connector = Connector()
	prevOutputHash = None
	prevOutputIdx = 0
	inputAmount = 0
	outputAmount = 0
	wif = None
	senderAddr = None
	receiverAddr = None
	if request.method == 'POST' and 'prevOutputHash' in request.form and 'prevOutputIdx' in request.form and 'wif' in request.form \
		and 'senderAddr' in request.form and 'receiverAddr' in request.form:
		prevOutputHash = str(request.form['prevOutputHash'].strip())
		prevOutputIdx = int(request.form['prevOutputIdx'].strip())
		wif = str(request.form['wif'].strip())
		inputAmount = float(request.form['inputAmount'].strip())
		outputAmount = float(request.form['outputAmount'].strip())
		senderAddr = str(request.form['senderAddr'].strip())
		receiverAddr = str(request.form['receiverAddr'].strip())
		outputs = [(utils.addressToScriptPubKey(receiverAddr), utils.convertBCHtoSatoshis(outputAmount)), \
			(utils.addressToScriptPubKey(senderAddr), utils.convertBCHtoSatoshis(inputAmount - outputAmount) - FEE)]
		transaction = Transaction(prevOutputHash, prevOutputIdx, wif, inputAmount, senderAddr, outputs)
		signedTrx = transaction.buildSignedTransaction()
		connector.sendTrxMsg(signedTrx)
		return render_template('result.html', txid=binascii.hexlify(utils.doubleSHA256(signedTrx)))

	return render_template('index.html')

if __name__ == '__main__':
	app.run()
