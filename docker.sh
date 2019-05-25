#!/bin/bash
docker stop bitcoin-cash-trx || true && docker rm bitcoin-cash-trx || true
docker build -t bitcoin-cash-trx .
docker run --name bitcoin-cash-trx -p 0.0.0.0:5000:5000 bitcoin-cash-trx