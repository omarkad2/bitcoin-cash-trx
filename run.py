from flask import Flask, render_template, request, abort
from wtforms import StringField, FloatField, validators, SubmitField
from flask_wtf import Form
from flask_bootstrap import Bootstrap
from transaction import Transaction, TxIn
from connector import Connector
from threading import Thread
import os
import requests
import binascii
import utils
import logging
import time


logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['SECRET_KEY'] = binascii.hexlify(os.urandom(10))
Bootstrap(app)

FEE = 2000.0
connector = Connector()
class TransactionForm(Form):
    wif = StringField('Sender WIF Key', [validators.DataRequired("52 characters base58, starts with a 'K' or 'L'")], render_kw={"placeholder": "Sender Private Key WIF Compressed"})
    senderAddr = StringField('Sender Address', [validators.DataRequired("The sender address is mandatory")], render_kw={"placeholder": "Sender BCH Address"})
    receiverAddr = StringField('Receiver Address', [validators.DataRequired("The receiver address is mandatory")], render_kw={"placeholder": "Receiver BCH Address"})
    amount = FloatField('Amount', [validators.DataRequired("The amount should be specified in BCH")], render_kw={"placeholder": "Amount to send in BCH"})
    submit = SubmitField('Send')

@app.route('/', methods=['GET', 'POST'])
def index():
    form = TransactionForm()
    error = ""
    if request.method == 'POST' and form.validate_on_submit():
        # Get Input Amount & Sender Legacy Address
        senderResp = requests.get('https://api.blockchair.com/bitcoin-cash/dashboards/address/'+form.senderAddr.data)
        senderDetails = senderResp.json()['data'][form.senderAddr.data]['address']
        if senderDetails['formats'] is None:
            error = "Sender address '{}' is invalid".format(form.senderAddr.data)
        else :
            senderLegacyAddress = str(senderDetails['formats']['legacy'])
            senderCashAddress = str(senderDetails['formats']['cashaddr'])
            # check if WIF compatible with sender Address
            if not utils.checkWifAddressCompatibility(str(form.wif.data), senderLegacyAddress):
                error = "WIF is not compatible with address : {}.".format(senderLegacyAddress)
            else :
                initialBalance = float(senderDetails['balance'])
                logging.debug("Is {} > {} + {}".format(initialBalance, utils.convertBCHtoSatoshis(form.amount.data), FEE))
                if utils.convertSatoshistoBCH(initialBalance) < form.amount.data + utils.convertSatoshistoBCH(FEE):
                    error = "Insufficient balance. You only have {} BCH (< {} BCH + fee)  on this address.".format(utils.convertSatoshistoBCH(initialBalance), form.amount.data)
                else :
                    # Get Receiver Legacy Address
                    receiverResp = requests.get('https://api.blockchair.com/bitcoin-cash/dashboards/address/'+form.receiverAddr.data)
                    receiverDetails = receiverResp.json()['data'][form.receiverAddr.data]['address']
                    if receiverDetails['formats'] is None:
                        error = "Receiver address '{}' is invalid".format(form.receiverAddr.data)
                    else :
                        receiverLegacyAddress = str(receiverDetails['formats']['legacy'])
                        # Get Previous Transaction Hash & Output Index
                        inputs = []
                        transactions = senderResp.json()['data'][form.senderAddr.data]['transactions']
                        for trx in transactions:
                            prevTrxHash = str(trx)
                            trxResp = requests.get('https://api.blockchair.com/bitcoin-cash/dashboards/transactions/'+prevTrxHash)
                            transactionDetails = trxResp.json()['data'][prevTrxHash]
                            inputAmount = 0
                            prevOutputIdx = 0
                            for output in transactionDetails['outputs']:
                                if output['recipient'] == senderCashAddress:
                                    prevOutputIdx = int(output['index'])
                                    inputAmount = float(output['value'])
                                    break
                            inputs.append(TxIn(prevTrxHash, prevOutputIdx, inputAmount))

                        # Create New Transaction
                        transaction = Transaction(inputs, initialBalance,
                                utils.wifToPrivateKey(str(form.wif.data)), senderLegacyAddress, receiverLegacyAddress, utils.convertBCHtoSatoshis(form.amount.data), FEE)
                        signedTrx = transaction.buildSignedTransaction()
                        logging.info("Raw Transaction {}".format(binascii.hexlify(signedTrx)))
                        success = connector.sendTrxMsg(signedTrx)
                        if not success:
                            error = "Something went wrong"
                        else :
                            return render_template('result.html', txid=binascii.hexlify(utils.doubleSHA256(signedTrx)[::-1]))

    return render_template('index.html', form=form, error=error, fee=utils.convertSatoshistoBCH(FEE))

if __name__ == '__main__':
    app.run("0.0.0.0")
    # Thread(target=connector.listen).start()
