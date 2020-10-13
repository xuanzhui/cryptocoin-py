# -*- coding: utf-8 -*-
"""
has dependency of web3
check https://github.com/ethereum/web3.py
pip install web3
"""

import web3
import eth_utils
import requests

# 1 as MainNet, 3 as Ropsten TestNet
CHAIN_ID = 1


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
           'chainId': CHAIN_ID}

    signed_tx = web3.Account.signTransaction(txn, private_key)

    return signed_tx.rawTransaction.hex(), signed_tx.hash.hex()


# erc20 transfer method param
def standard_token_transaction_data_field(to_address, amount):
    data = '0xa9059cbb'
    if to_address.startswith('0x'):
        addr = to_address[2:]
    else:
        addr = to_address
    data += addr.lower().zfill(64)
    amount_hex = format(amount, 'x')
    data += amount_hex.zfill(64)
    return data


# token_amount must be (display amount) * 10^(decimals, most contract use the default value 18)
def generate_token_transaction(to_addr, token_amount, gas_price_wei, nonce, private_key):
    contract_address = '==> contract address'

    txn = {'to': contract_address,
           'value': 0,
           'gas': 55000,
           'gasPrice': gas_price_wei,
           'nonce': nonce,
           'chainId': CHAIN_ID,
           'data': standard_token_transaction_data_field(to_addr, token_amount)}

    signed_tx = web3.Account.signTransaction(txn, private_key)

    return signed_tx.rawTransaction.hex(), signed_tx.hash.hex()


def send_raw_txn_etherscan_node(raw_txn):
    send_data = {'module': 'proxy', 'action': 'eth_sendRawTransaction',
                 'hex': raw_txn, 'apikey': 'YZ1ZBQIMIS5UG5MCCJ3VU9JYBVFENPRCNK'}
    resp = requests.post('https://api.etherscan.io/api', data=send_data)

    if resp.status_code == 200:
        res_map = resp.json()
        if res_map and res_map.get('result'):
            return 'succ', res_map.get('result')

    return 'err', resp.text


if __name__ == '__main__':
    pri_hex, address = gen_key_pair()
    print('private key in hex format:', pri_hex)
    print('address:', address)

    print('address from private key:', address_from_pri_hex(pri_hex))

    from decimal import Decimal

    # raw_hex, txn_hash = sign_txn('===> receiver address',
    #                              int(Decimal(str(0.0015)) * Decimal(10**18)),
    #                              10 * (10 ** 9),
    #                              25,
    #                              '====>private key')
    #
    # print('raw hex:', raw_hex)
    # print('txn hash:', txn_hash)

    raw_hex, txn_hash = generate_token_transaction('===> receiver address',
                                                   int(Decimal('8333.333333') * Decimal(10**18)),
                                                   10 * (10 ** 9),
                                                   40,
                                                   '====>private key')

    print('raw hex:', raw_hex)
    print('txn hash:', txn_hash)
