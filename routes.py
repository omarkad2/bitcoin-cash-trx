from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def index():
	error = None
	trxId = None
	wif = None
	senderAddr = None
	receiverAddr = None
	if request.method == 'POST' and 'trxId' in request.form and 'wif' in request.form and 'senderAddr' in request.form and 'receiverAddr' in request.form:
		trxId = request.form['trxId']
		wif = request.form['wif']
		senderAddr = request.form['senderAddr']
		receiverAddr = request.form['receiverAddr']
	else :
		error = 'An error has occured'
	return render_template('index.html', error=error, trxId=trxId, wif=wif, senderAddr=senderAddr, receiverAddr=receiverAddr)

if __name__ == '__main__':
	app.run()
