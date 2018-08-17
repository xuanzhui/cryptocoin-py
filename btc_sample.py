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
from pycoin.ui import address_for_pay_to_script, script_obj_from_address
from pycoin.tx.pay_to import build_hash160_lookup, ScriptMultisig, build_p2sh_lookup, ScriptPayToAddressWit
from pycoin.serialize import h2b_rev
from hashlib import sha256
import requests

# 'BTC' => "Bitcoin", "mainnet"
# 'XTN' => "Bitcoin", "testnet3"
NET_CODE = 'BTC'

PRI_KEY_MIN = int('0x1', 16)
PRI_KEY_MAX = int('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140', 16)


def address_from_pri_hex(pri_hex):
    my_key = Key(secret_exponent=int(pri_hex, 16),
                 prefer_uncompressed=False, netcode=NET_CODE)

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
    my_key = Key(secret_exponent=key,
                 prefer_uncompressed=False, netcode=NET_CODE)

    return pri_hex, my_key.address()


def address_from_wif(wif):
    my_key = Key.from_text(wif)

    return my_key.address()


def gen_key_pair_as_wif():
    key, pri_hex = _gen_pri_key()

    my_key = Key(secret_exponent=key,
                 prefer_uncompressed=False, netcode=NET_CODE)

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

        _un_spent.append(Spendable(balance, script_obj_from_address(address, netcodes=[NET_CODE]).script(),
                                   tx_id_b, idx))

    _txs_out = []
    for balance, receiver_address in tx_outs:
        _txs_out.append(TxOut(balance, script_obj_from_address(receiver_address, netcodes=[NET_CODE]).script()))

    version, lock_time = 1, 0
    tx = Tx(version, _txs_in, _txs_out, lock_time)
    tx.set_unspents(_un_spent)

    solver = build_hash160_lookup([int(pri_hex, 16) for pri_hex in in_keys])
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
    pay_to_multisig_script = ScriptMultisig(m, pub_keys).script()
    return address_for_pay_to_script(pay_to_multisig_script, netcode=NET_CODE), pay_to_multisig_script.hex()


def gen_2of3_multisig_key_pair():
    key_pairs = []
    for i in range(0, 3):
        key, pri_hex = _gen_pri_key()
        my_key = Key(secret_exponent=key,
                     prefer_uncompressed=False, netcode=NET_CODE)

        # return wif or hex format, use your own strategy
        key_pairs.append((my_key.wif(), my_key.sec_as_hex()))

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

        _un_spent.append(Spendable(balance, script_obj_from_address(address, netcodes=[NET_CODE]).script(),
                                   tx_id_b, idx))

    _txs_out = []
    for balance, receiver_address in tx_outs:
        _txs_out.append(TxOut(balance, script_obj_from_address(receiver_address, netcodes=[NET_CODE]).script()))

    version, lock_time = 1, 0
    tx = Tx(version, _txs_in, _txs_out, lock_time)
    tx.set_unspents(_un_spent)

    # construct hash160_lookup[hash160] = (secret_exponent, public_pair, compressed) for each individual key
    hash160_lookup = build_hash160_lookup([Key.from_text(wif_key).secret_exponent() for wif_key in wif_keys])

    for i in range(0, len(tx_ins)):
        # you can add some conditions that if the input script is not p2sh type, not provide p2sh_lookup,
        # so that all kinds of inputs can work together
        p2sh_lookup = build_p2sh_lookup([binascii.unhexlify(tx_ins[i][-1])])
        tx.sign_tx_in(hash160_lookup, i, tx.unspents[i].script, hash_type=SIGHASH_ALL, p2sh_lookup=p2sh_lookup)

    return tx.as_hex(), tx.id()


def pkh_segwit_address_from_wif(wif):
    """
    The P2SH redeemScript is always 22 bytes.
    It starts with a OP_0, followed by a canonical push of the keyhash (i.e. 0x0014{20-byte keyhash})

    Same as any other P2SH, the scriptPubKey is OP_HASH160 hash160(redeemScript) OP_EQUAL
    """
    my_key = Key.from_text(wif)
    script = ScriptPayToAddressWit(b'\0', my_key.hash160()).script()
    script_hex = binascii.hexlify(script).decode()
    return address_for_pay_to_script(script, netcode=NET_CODE), script_hex


if __name__ == '__main__':
    pri_hex, address = gen_key_pair()
    print('private key in hex format:', pri_hex)
    print('address from compressed public key:', address)

    print('address from private key:', address_from_pri_hex(pri_hex))

    wif_key, address = gen_key_pair_as_wif()
    print('private key in wallet import format:', wif_key)
    print('address from compressed public key:', address)

    print('address from private key:', address_from_wif(wif_key))

    # (utxo id, utxo index, balance in satoshi, sender address)
    tx_ins = [('577ed0c91dfa959f539952e8b4e6e625473260745fd62ea6283c5c3418d94870', 0, 13122,
               '17SRgFPdFRVdMGxcMkCBCXPvNnCPLg9gWe'),
              ('67a690184f71ea152ece6728a85aa889d5eb735e4e2fe51c684e8ef8f933a71d', 0, 1573252,
               '17SRgFPdFRVdMGxcMkCBCXPvNnCPLg9gWe')
              ]
    in_keys = ['===>hex format key for input1',
               '===>hex format key for input2'
               ]
    tx_outs = [(1532624, '17SRgFPdFRVdMGxcMkCBCXPvNnCPLg9gWe'),
               (50000, '3FMyytPExvoc8dV8oeoqoDzqGr8qeEVUGu')
               ]

    raw_hex, tx_id = spend_pkh_fund(tx_ins, in_keys, tx_outs)
    print('signed raw hex:')
    print(raw_hex)
    print('txn id/hash:')
    print(tx_id)

    print('calculated txn id:')
    print(calculate_txid_from_raw_hex(raw_hex))

    # ==============> multi sign, please pay attention here only supports inputs from the same address
    mulsig_info, key_pairs = gen_2of3_multisig_key_pair()
    print('address:', mulsig_info[0])
    print('redeem script:', mulsig_info[1])
    print('partial keys:', key_pairs)

    redeem_script = '522103f014ab0490259b0dab5f84fa871e7e54845749d054343606813197e531a8c01d' \
                    '210203224e6af552892d416a53be4eaae6c517d99314e9199c1d38936f2e97476690' \
                    '2102dc5a0ba9a71cdf3fd4cba70c0994037ae4fd81b7ac48cbade1f0d73a919d86f953ae'
    tx_ins = [('3e0594b046d2109756668d6a2d8fcf25390aeacc00f92087498e286aa8171a03', 0, 200000,
               '3P5ifvQge9pddxVDQQJW7Byk9HKFAWiA5i',
               redeem_script),
              ('eb830cf7ff658f12db6cf7fd8e2b1bee2995a0c1385e65e25cfc74b311b45752', 0, 100000,
               '3P5ifvQge9pddxVDQQJW7Byk9HKFAWiA5i',
               redeem_script)
              ]
    # pick two keys from the generated key pairs
    partial_keys = ['===>wif key1',
                    '===>wif key2']
    tx_outs = [(294000, '17SRgFPdFRVdMGxcMkCBCXPvNnCPLg9gWe')]

    raw_hex, tx_id = spend_sh_fund(tx_ins, partial_keys, tx_outs)
    print('signed raw hex:')
    print(raw_hex)
    print('txn id/hash:')
    print(tx_id)

    # ==============> segwit P2SH-P2WPKH
    wif_key = '===>'
    address, redeem = pkh_segwit_address_from_wif(wif_key)
    print(address, redeem)
    tx_ins = [('da3ad575437b093fe3d939f549dbec49be4f6b49f121a469f14ea0a9e216ed9c', 1, 50000,
               '3FMyytPExvoc8dV8oeoqoDzqGr8qeEVUGu', '0014109031aea56f925a006847e1eece20cbd8c632fe')
              ]
    in_keys = [wif_key
               ]
    tx_outs = [(48070, '17SRgFPdFRVdMGxcMkCBCXPvNnCPLg9gWe')
               ]

    raw_hex, tx_id = spend_sh_fund(tx_ins, in_keys, tx_outs)
    print('signed raw hex:')
    print(raw_hex)
    print('txn id/hash:')
    print(tx_id)
