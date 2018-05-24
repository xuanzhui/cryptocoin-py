# -*- coding: utf-8 -*-
"""
has dependency of pycoin
check https://github.com/richardkiss/pycoin
pip install pycoin
"""

from pycoin.key import Key
import os
import binascii
from pycoin.tx.Tx import Tx, SIGHASH_ALL
from pycoin.tx.TxIn import TxIn
from pycoin.tx.TxOut import TxOut
from pycoin.tx.Spendable import Spendable
from pycoin.ui import standard_tx_out_script
from pycoin.tx.pay_to import build_hash160_lookup
from pycoin.serialize import h2b_rev
from hashlib import sha256

# 'BTC' => "Bitcoin", "mainnet"
# 'XTN' => "Bitcoin", "testnet3"
NET_CODE = 'XTN'


def address_from_pri_hex(pri_hex):
    my_key = Key(secret_exponent=int(pri_hex, 16),
                 prefer_uncompressed=False, netcode=NET_CODE)

    return my_key.address()


def gen_key_pair():
    sec = os.urandom(32)
    pri_hex = binascii.hexlify(sec).decode()
    my_key = Key(secret_exponent=int(pri_hex, 16),
                 prefer_uncompressed=False, netcode=NET_CODE)

    return pri_hex, my_key.address()


def address_from_wif(wif):
    my_key = Key.from_text(wif)

    return my_key.address()


def gen_key_pair_as_wif():
    sec = os.urandom(32)
    pri_hex = binascii.hexlify(sec).decode()
    my_key = Key(secret_exponent=int(pri_hex, 16),
                 prefer_uncompressed=False, netcode=NET_CODE)

    return my_key.wif(), my_key.address()


def p2pkh_tx(tx_ins, in_keys, tx_outs):
    _txs_in = []
    _un_spent = []
    for tx_id, idx, balance, address in tx_ins:
        # must h2b_rev NOT h2b
        tx_id_b = h2b_rev(tx_id)
        _txs_in.append(TxIn(tx_id_b, idx))

        _un_spent.append(Spendable(balance, standard_tx_out_script(address), tx_id_b, idx))

    _txs_out = []
    for balance, receiver_address in tx_outs:
        _txs_out.append(TxOut(balance, standard_tx_out_script(receiver_address)))

    version, lock_time = 1, 0
    tx = Tx(version, _txs_in, _txs_out, lock_time)
    tx.set_unspents(_un_spent)

    solver = build_hash160_lookup([int(pri_hex, 16) for pri_hex in in_keys])
    signed_tx = tx.sign(solver, hash_type=SIGHASH_ALL)

    return signed_tx.as_hex(), signed_tx.id()


def calculate_txid_from_raw_hex(raw_hex):
    # raw hex to txid
    # detail https://bitcoin.stackexchange.com/questions/32765/how-do-i-calculate-the-txid-of-this-raw-transaction
    raw_bytes = binascii.unhexlify(raw_hex)
    return binascii.hexlify(sha256(sha256(raw_bytes).digest()).digest()[::-1]).decode()


def estimate_p2pkh_tx_bytes(vin, vout, is_compressed=True):
    """
    estimated bytes multiple fee per byte result in txn fee
    for recommend fee per byte, check https://bitcoinfees.earn.com/api
    :param vin: input count
    :param vout: output count
    :param is_compressed: is public key compressed
    :return: estimated byte count
    """
    if is_compressed:
        return vin * 148 + vout * 34 + 10 + vin
    else:
        return vin * 180 + vout * 34 + 10 + vin


if __name__ == '__main__':
    pri_hex, address = gen_key_pair()
    print('private key in hex format:', pri_hex)
    print('address from compressed public key:', address)

    print('address from private key:', address_from_pri_hex(pri_hex))

    wif_key, address = gen_key_pair_as_wif()
    print('private key in wallet import format:', wif_key)
    print('address from compressed public key:', address)

    print('address from private key:', address_from_wif(wif_key))

    tx_ins = [('e7c8e9c6db79a665bbdffd03adaff22ceeb975b00480797561a736de4b5ef575', 0, 20000000,
               'miMz95qmcq3ZHVY6UVQJasMRU2RoxtRaU8'),
              ('cf60e01bfb63b18bc95d9674f026c4109c5215accfee21d9adb5c300c41cce84', 1, 63916800,
               'miMz95qmcq3ZHVY6UVQJasMRU2RoxtRaU8')]
    in_keys = ['==>private key in hex format for first input',
               '==>private key in hex format for second input']
    tx_outs = [(25000000, 'n3yCWzctsFspunWTKWfBACWvM7ffX3xZLd'),
               (58875500, 'miMz95qmcq3ZHVY6UVQJasMRU2RoxtRaU8')]

    raw_hex, tx_id = p2pkh_tx(tx_ins, in_keys, tx_outs)
    print('signed raw hex:')
    print(raw_hex)
    print('txn id/hash:')
    print(tx_id)

    print('calculated txn id:')
    print(calculate_txid_from_raw_hex(raw_hex))
