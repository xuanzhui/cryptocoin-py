# -*- coding: utf-8 -*-
"""
has dependency of pycoin
check https://github.com/richardkiss/pycoin
pip install pycoin
"""

from pycoin.key.Key import Key
import os
import binascii
from pycoin.coins.bitcoin.Tx import Tx
from pycoin.satoshi.flags import SIGHASH_ALL
from pycoin.coins.bitcoin.TxIn import TxIn
from pycoin.coins.bitcoin.TxOut import TxOut
from pycoin.coins.bitcoin.Spendable import Spendable
from pycoin.coins.bitcoin.Solver import BitcoinSolver
from pycoin.solve.utils import build_hash160_lookup, build_p2sh_lookup
from pycoin.encoding.hexbytes import h2b_rev
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.networks.registry import network_for_netcode

from hashlib import sha256
import requests

# 'BTC' => "Bitcoin", "mainnet"
# 'XTN' => "Bitcoin", "testnet3"
NET_CODE = 'BTC'

PRI_KEY_MIN = int('0x1', 16)
PRI_KEY_MAX = int('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140', 16)

network = network_for_netcode(NET_CODE)
NORMAL_KEY = Key.make_subclass(network, secp256k1_generator)


def address_from_pri_hex(pri_hex):
    my_key = NORMAL_KEY(secret_exponent=int(pri_hex, 16))

    return my_key.address()


def _gen_pri_key():
    sec = os.urandom(32)
    pri_hex = binascii.hexlify(sec).decode()

    key = int(pri_hex, 16)
    if key < PRI_KEY_MIN or key > PRI_KEY_MAX:
        raise ValueError('error on generating private key')

    return key, pri_hex


def gen_key_pair():
    key, pri_hex = _gen_pri_key()
    my_key = NORMAL_KEY(secret_exponent=key)

    return pri_hex, my_key.address()


def address_from_wif(wif):
    my_key = network.parse.wif(wif)
    return my_key.address()


def gen_key_pair_as_wif():
    key, pri_hex = _gen_pri_key()

    my_key = NORMAL_KEY(secret_exponent=key)

    return my_key.wif(), my_key.address()


def spend_pkh_fund(tx_ins, in_keys, tx_outs):
    """
    p2pkh address send to p2pkh p2sh transaction
    :param tx_ins: list with tuple(tx_id, idx, balance, address)
    :param in_keys: list of private keys in hex format corresponding to each input
    :param tx_outs: balance, receiver_address
    :return: raw hex and tx id
    """
    _txs_in = []
    _un_spent = []
    for tx_id, idx, balance, address in tx_ins:
        # must h2b_rev NOT h2b
        tx_id_b = h2b_rev(tx_id)
        _txs_in.append(TxIn(tx_id_b, idx))

        script = network.contract.for_address(address)
        _un_spent.append(Spendable(balance, script, tx_id_b, idx))

    _txs_out = []
    for balance, receiver_address in tx_outs:
        _txs_out.append(TxOut(balance, network.contract.for_address(receiver_address)))

    version, lock_time = 1, 0
    tx = Tx(version, _txs_in, _txs_out, lock_time)
    tx.set_unspents(_un_spent)

    solver = build_hash160_lookup([int(pri_hex, 16) for pri_hex in in_keys], [secp256k1_generator])
    tx.sign(solver, hash_type=SIGHASH_ALL)

    return tx.as_hex(), tx.id()


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


def recommend_satoshi_per_byte():
    recommend = 20

    try:
        resp = requests.get('https://bitcoinfees.earn.com/api/v1/fees/recommended')

        if resp.status_code == 200:
            fees = resp.json()
            if fees.get('halfHourFee'):
                recommend = fees.get('halfHourFee')

    except Exception as e:
        print('fail to get recommend fee, ', e)

    return recommend


# return address and redeem script
def get_multisig_address(m, pub_keys):
    pay_to_multisig_script = network.contract.for_multisig(m, pub_keys)
    return network.address.for_p2s(pay_to_multisig_script), pay_to_multisig_script.hex()


def gen_2of3_multisig_key_pair():
    key_pairs = []
    for i in range(0, 3):
        key, pri_hex = _gen_pri_key()
        my_key = NORMAL_KEY(secret_exponent=key)

        # return wif and pub hex format
        key_pairs.append((my_key.wif(), binascii.hexlify(my_key.sec())))

    return get_multisig_address(2, [binascii.unhexlify(key[1]) for key in key_pairs]), key_pairs


def spend_sh_fund(tx_ins, wif_keys, tx_outs):
    """
    spend script hash fund
    the key point of an input comes from multisig address is that,
    its sign script is combined with several individual signs
    :param tx_ins: list with tuple(tx_id, idx, balance, address, redeem_script)
    :param wif_keys: private keys in wif format,
        technical should be the same order with the pubkey in redeem script,
        but pycoin has inner control, so here order is not mandatory
    :param tx_outs: balance, receiver_address
    :return: raw hex and tx id
    """
    _txs_in = []
    _un_spent = []
    for tx_id, idx, balance, address, _ in tx_ins:
        # must h2b_rev NOT h2b
        tx_id_b = h2b_rev(tx_id)
        _txs_in.append(TxIn(tx_id_b, idx))

        _un_spent.append(Spendable(balance, network.contract.for_address(address),
                                   tx_id_b, idx))

    _txs_out = []
    for balance, receiver_address in tx_outs:
        _txs_out.append(TxOut(balance, network.contract.for_address(receiver_address)))

    version, lock_time = 1, 0
    tx = Tx(version, _txs_in, _txs_out, lock_time)
    tx.set_unspents(_un_spent)

    # construct hash160_lookup[hash160] = (secret_exponent, public_pair, compressed) for each individual key
    hash160_lookup = build_hash160_lookup([network.parse.wif(wif_key).secret_exponent() for wif_key in wif_keys],
                                          [secp256k1_generator])

    for i in range(0, len(tx_ins)):
        # you can add some conditions that if the input script is not p2sh type, not provide p2sh_lookup,
        # so that all kinds of inputs can work together
        p2sh_lookup = build_p2sh_lookup([binascii.unhexlify(tx_ins[i][-1])])
        r = BitcoinSolver(tx).solve(hash160_lookup, i, hash_type=SIGHASH_ALL, p2sh_lookup=p2sh_lookup)
        if isinstance(r, bytes):
            tx.txs_in[i].script = r
        else:
            tx.txs_in[i].script = r[0]
            tx.set_witness(i, r[1])

    return tx.as_hex(), tx.id()


def pkh_segwit_address_from_wif(wif):
    """
    The redeemScript is always 22 bytes.
    It starts with a OP_0, followed by a canonical push of the keyhash (i.e. 0x0014{20-byte keyhash})

    return Native SegWit (bech32): addresses start with bc1
    """
    my_key = network.parse.wif(wif)
    segwit_script = network.contract.for_p2pkh_wit(my_key.hash160())
    return network.address.for_p2pkh_wit(my_key.hash160()), segwit_script.hex()


def get_utxo(address):
    url = f'https://insight.bitpay.com/api/addr/{address}/utxo'
    resp = requests.get(url)
    if resp.status_code == 200:
        return resp.json()
    else:
        return None


def broadcast_raw(raw_hex):
    url = 'https://insight.bitpay.com/api/tx/send'
    resp = requests.post(url, data={'rawtx': raw_hex})
    if resp.status_code == 200:
        return resp.text
    else:
        return resp.text


if __name__ == '__main__':
    pri_hex, address = gen_key_pair()
    print('private key in hex format:', pri_hex)
    print('address from compressed public key:', address)

    # print('address from private key:', address_from_pri_hex('your private key in hex format'))

    # wif_key, address = gen_key_pair_as_wif()
    # print('private key in wallet import format:', wif_key)
    # print('address from compressed public key:', address)

    # print('address from private key:', address_from_wif('your private key in wif format'))

    # (utxo id, utxo index, balance in satoshi, sender address)
    # tx_ins = [('tx id', idx, balance, 'sender address'),
    #           ]
    # in_keys = ['sender private key in hex format',
    #            ]
    # fee = estimate_p2pkh_tx_bytes(len(tx_ins), 2) * recommend_satoshi_per_byte()
    # tx_outs = [(sendAmt1, 'receiver1 address'),
    #            (balance - sendAmt - fee, 'receiver2 address')]

    # raw_hex, tx_id = spend_pkh_fund(tx_ins, in_keys, tx_outs)
    # print('signed raw hex:')
    # print(raw_hex)
    # print('txn id/hash:')
    # print(tx_id)

    # print(broadcast_raw(raw_hex))

    # print('calculated txn id:')
    # print(calculate_txid_from_raw_hex(raw_hex))

    # ==============> multi sign, please pay attention here only supports inputs from the same address
    # mulsig_info, key_pairs = gen_2of3_multisig_key_pair()
    # print('address:', mulsig_info[0])
    # print('redeem script:', mulsig_info[1])
    # print('partial keys:', key_pairs)

    # redeem_script = mulsig_info[1]
    # tx_ins = [('tx id', idx, balance, 'sender address', redeem_script),
    #           ]
    # pick two keys from the generated key pairs in order
    # partial_keys = ['one of private keys in wif format',
    #                 'one of private keys in wif format']
    # tx_outs = [(sendAmt1, 'receiver1 address'),
    #            (sendAmt2, 'receiver2 address'),
    #            ]
    #
    # raw_hex, tx_id = spend_sh_fund(tx_ins, partial_keys, tx_outs)
    # print('signed raw hex:')
    # print(raw_hex)
    # print('txn id/hash:')
    # print(tx_id)

    # # ==============> segwit native P2WPKH
    # wif_key = '==>'
    # address, redeem = pkh_segwit_address_from_wif(wif_key)
    # print(address, redeem)

    # tx_ins = [('tx id', idx, balance, 'sender address', 'segwit redeem script'),
    #           ]
    # in_keys = ['sender key in wif format',
    #            ]
    # tx_outs = [(sendAmt1, 'receiver1 address'),
    #            (sendAmt2, 'receiver2 address'),
    #            ]
    #
    # raw_hex, tx_id = spend_sh_fund(tx_ins, in_keys, tx_outs)
    # print('signed raw hex:')
    # print(raw_hex)
    # print('txn id/hash:')
    # print(tx_id)

    # print(get_utxo('13EeuKWMzgdcqFEoAmEVWVd8ZdbwjvVD5s'))
