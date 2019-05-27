from flask import Flask, render_template, request
from wtforms import StringField, FloatField, validators, SubmitField
from flask_wtf import Form
from flask_bootstrap import Bootstrap
from transaction import Transaction, TxIn, TxOut
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

FEE = 1000.0
API_ADDR_URL = 'https://api.blockchair.com/bitcoin-cash/dashboards/address/'
API_TRX_URL = 'https://api.blockchair.com/bitcoin-cash/dashboards/transaction/'
connector = Connector()
class TransactionForm(Form):
    wif = StringField('Sender WIF Key', [validators.DataRequired('52 characters base58, starts with a \'K\' or \'L\'')], render_kw={'placeholder': 'Sender Private Key WIF Compressed'})
    senderAddr = StringField('Sender Address', [validators.DataRequired('The sender address is mandatory')], render_kw={'placeholder': 'Sender BCH Address'})
    receiverAddr = StringField('Receiver Address', [validators.DataRequired('The receiver address is mandatory')], render_kw={'placeholder': 'Receiver BCH Address'})
    amount = FloatField('Amount', [validators.DataRequired('The amount should be specified in BCH')], render_kw={'placeholder': 'Amount to send in BCH'})
    submit = SubmitField('Send')

@app.route('/', methods=['GET', 'POST'])
def index():
    form = TransactionForm()
    if request.method == 'POST' and form.validate_on_submit():
        # Get Sender Legacy Details
        senderResp = requests.get(API_ADDR_URL+form.senderAddr.data)
        senderDetails = senderResp.json()['data'][form.senderAddr.data]
        if senderDetails['address']['formats'] is None:
            return render_template('index.html', form=form, error='Sender address \'{}\' is invalid'.format(form.senderAddr.data), fee=utils.convertSatoshistoBCH(FEE))
        senderLegacyAddress = str(senderDetails['address']['formats']['legacy'])
        senderCashAddress = str(senderDetails['address']['formats']['cashaddr'])
        transactions = senderDetails['transactions']
        # Check if WIF compatible with sender Address
        if not utils.checkWifAddressCompatibility(str(form.wif.data), senderLegacyAddress):
            return render_template('index.html', form=form, error='WIF is not compatible with address : {}.'.format(senderLegacyAddress), fee=utils.convertSatoshistoBCH(FEE))
        # Check if balance is sufficient
        initialBalance = float(senderDetails['address']['balance'])
        logging.debug('Is {} > {} + {} ?'.format(initialBalance, utils.convertBCHtoSatoshis(form.amount.data), FEE))
        if utils.convertSatoshistoBCH(initialBalance) < form.amount.data + utils.convertSatoshistoBCH(FEE):
            return render_template('index.html', form=form, error='Insufficient balance. You only have {} BCH (< {} BCH + fee)  on this address.'.format(utils.convertSatoshistoBCH(initialBalance), form.amount.data), fee=utils.convertSatoshistoBCH(FEE))
        # Get Receiver Details
        receiverResp = requests.get(API_ADDR_URL+form.receiverAddr.data)
        receiverDetails = receiverResp.json()['data'][form.receiverAddr.data]
        if receiverDetails['address']['formats'] is None:
            return render_template('index.html', form=form, error='Receiver address \'{}\' is invalid'.format(form.receiverAddr.data), fee=utils.convertSatoshistoBCH(FEE))
        receiverLegacyAddress = str(receiverDetails['address']['formats']['legacy'])
        # Get Transaction Inputs
        inputs = buildTxIns(senderCashAddress, transactions)
        # Get Transaction Outputs
        outputs = buildTxOuts(senderLegacyAddress, receiverLegacyAddress, initialBalance, utils.convertBCHtoSatoshis(form.amount.data), FEE)

        # Create Transaction
        transaction = Transaction(utils.wifToPrivateKey(str(form.wif.data)), senderLegacyAddress, inputs, outputs)
        signedTrx = transaction.buildSignedTransaction()
        logging.info('Raw Transaction {}'.format(binascii.hexlify(signedTrx)))

        # Broadcast Transaction
        connector.sendTrxMsg(signedTrx)
        return render_template('result.html', txid=binascii.hexlify(utils.doubleSHA256(signedTrx)[::-1]))

    return render_template('index.html', form=form, error='', fee=utils.convertSatoshistoBCH(FEE))

def buildTxIns(senderCashAddress, trxHashes):
    inputs = []
    for trxHash in trxHashes:
        trxResp = requests.get(API_TRX_URL+trxHash)
        trxData = trxResp.json()['data']
        trxDetails = trxData[trxHash]
        inputAmount = 0
        prevOutputIdx = 0
        for output in trxDetails['outputs']:
            if output['recipient'] == senderCashAddress:
                prevOutputIdx = int(output['index'])
                inputAmount = float(output['value'])
                spent = bool(output['is_spent'])
                break
        if not spent : inputs.append(TxIn(trxHash, prevOutputIdx, inputAmount))
    return inputs

def buildTxOuts(senderLegacyAddress, receiverLegacyAddress, initialBalance, amount, fee):
    return [TxOut(utils.addressToScriptPubKey(receiverLegacyAddress), amount), \
            TxOut(utils.addressToScriptPubKey(senderLegacyAddress), initialBalance - amount - fee)]

if __name__ == '__main__':
    app.run('0.0.0.0')
    # Thread(target=connector.listen).start()
