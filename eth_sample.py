# -*- coding: utf-8 -*-
"""
has dependency of web3
check https://github.com/ethereum/web3.py
pip install web3
"""

import web3
import eth_utils


def gen_key_pair():
    acc = web3.Account.create()
    return acc.privateKey.hex(), acc.address


def address_from_pri_hex(pri_hex):
    acc = web3.Account.privateKeyToAccount(pri_hex)
    return acc.address


def sign_txn(to_addr, amount_wei, gas_price_wei, nonce, private_key):
    txn = {'to': eth_utils.to_checksum_address(to_addr),
           'value': amount_wei,
           'gas': 21000,
           'gasPrice': gas_price_wei,
           'nonce': nonce,
           'chainId': 1}

    signed_tx = web3.Account.signTransaction(txn, private_key)

    return signed_tx.rawTransaction.hex(), signed_tx.hash.hex()


if __name__ == '__main__':
    pri_hex, address = gen_key_pair()
    print('private key in hex format:', pri_hex)
    print('address:', address)

    print('address from private key:', address_from_pri_hex(pri_hex))

    from decimal import Decimal

    raw_hex, txn_hash = sign_txn('===>address',
                                 int(Decimal(str(0.0015)) * Decimal(1e18)),
                                 10 * (10 ** 9),
                                 25,
                                 '====>private key')

    print('raw hex:', raw_hex)
    print('txn hash:', txn_hash)
