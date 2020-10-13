# -*- coding: utf-8 -*-
"""
has dependency of pycoin
check https://github.com/richardkiss/pycoin
pip install pycoin

usdt transaction is based on btc p2pkh transaction with OP_RETURN
"""

import binascii
from pycoin.coins.bitcoin.Tx import Tx
from pycoin.satoshi.flags import SIGHASH_ALL
from pycoin.coins.bitcoin.TxIn import TxIn
from pycoin.coins.bitcoin.TxOut import TxOut
from pycoin.coins.bitcoin.Spendable import Spendable
from pycoin.coins.bitcoin.Solver import BitcoinSolver
from pycoin.solve.utils import build_hash160_lookup, build_p2sh_lookup
from pycoin.encoding.hexbytes import h2b_rev
from btc_sample import estimate_p2pkh_tx_bytes
from btc_sample import recommend_satoshi_per_byte
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.networks.registry import network_for_netcode

network = network_for_netcode("BTC")
MIN_BTC_OUT = 546


def tether_tx(tx_ins, in_keys, send_amount, receiver, change_address):
    """
    simple usdt transaction

    different address's utxo can be used for mine fee,
    but should be aware sender is determined by the first input in the tx

    bitcoin change can also be sent back to different address,
    but should be aware receiver is indicated by the last output address that is not the sender

    :param tx_ins: utxo from the sender
    :param in_keys: list of private keys in hex format corresponding to each input
    :param send_amount: (display amount) * (10 ** 8)
    :param receiver: address to receive usdt
    :param change_address: address to receive btc change
    """
    _txs_in = []
    _un_spent = []
    total_bal = 0

    for tx_id, idx, balance, address in tx_ins:
        total_bal += balance

        # must h2b_rev NOT h2b
        tx_id_b = h2b_rev(tx_id)
        _txs_in.append(TxIn(tx_id_b, idx))

        _un_spent.append(Spendable(balance, network.contract.for_address(address), tx_id_b, idx))

    satoshi_per_byte = recommend_satoshi_per_byte()
    txn_fee = estimate_p2pkh_tx_bytes(len(tx_ins), 3) * satoshi_per_byte

    _txs_out = [TxOut(total_bal - txn_fee - MIN_BTC_OUT, network.contract.for_address(change_address)),
                TxOut(0, binascii.unhexlify(omni_tether_script(send_amount))),
                TxOut(MIN_BTC_OUT, network.contract.for_address(receiver))]

    version, lock_time = 1, 0
    tx = Tx(version, _txs_in, _txs_out, lock_time)
    tx.set_unspents(_un_spent)

    solver = build_hash160_lookup([int(pri_hex, 16) for pri_hex in in_keys], [secp256k1_generator])
    signed_tx = tx.sign(solver, hash_type=SIGHASH_ALL)

    return signed_tx.as_hex(), signed_tx.id()


def omni_tether_script(amount):
    """
    :param amount: (display amount) * (10 ** 8)
    :return omni tether script in hex format
    """

    prefix = "6a146f6d6e69000000000000001f"
    amount_hex = format(amount, 'x')
    amount_format = amount_hex.zfill(16)

    return prefix + amount_format


def tether_tx_flush(tx_ins, private_key, send_amount, receiver):
    """
    this is just a tool function that sends all btc and usdt fund to the same receiver address
    params are same with tether_tx
    """
    _txs_in = []
    _un_spent = []
    total_bal = 0

    for tx_id, idx, balance, address in tx_ins:
        total_bal += balance

        # must h2b_rev NOT h2b
        tx_id_b = h2b_rev(tx_id)
        _txs_in.append(TxIn(tx_id_b, idx))

        _un_spent.append(Spendable(balance, network.contract.for_address(address), tx_id_b, idx))

    txn_fee = estimate_p2pkh_tx_bytes(len(tx_ins), 2) * recommend_satoshi_per_byte()

    _txs_out = [TxOut(0, binascii.unhexlify(omni_tether_script(send_amount))),
                TxOut(total_bal - txn_fee, network.contract.for_address(receiver))]

    version, lock_time = 1, 0
    tx = Tx(version, _txs_in, _txs_out, lock_time)
    tx.set_unspents(_un_spent)

    solver = build_hash160_lookup([int(private_key, 16)] * len(tx_ins), [secp256k1_generator])
    signed_tx = tx.sign(solver, hash_type=SIGHASH_ALL)

    return signed_tx.as_hex(), signed_tx.id()


def tether_tx_sh(tx_ins, wif_keys, send_amount, receiver, change_address):
    """
    spend usdt having p2sh utxo
    WARNING!!! THIS FUNCTION IS NOT FULLY TESTED AS MY FUND WAS STOLEN BY A SON OF BITCH
        AFTER I BY ACCIDENT COMMITTED MY PRIVATE KEY!!!
    :param tx_ins: list with tuple(tx_id, idx, balance, address, redeem_script),
        redeem_script is required for p2sh utxo, set it None for p2pkh utxo
    :param wif_keys: private keys of the inputs
    :param send_amount: (display amount) * (10 ** 8)
    :param receiver: address to receive usdt
    :param change_address: address to receive btc change
    """
    _txs_in = []
    _un_spent = []
    total_bal = 0

    for tx_id, idx, balance, address, _ in tx_ins:
        total_bal += balance

        # must h2b_rev NOT h2b
        tx_id_b = h2b_rev(tx_id)
        _txs_in.append(TxIn(tx_id_b, idx))

        _un_spent.append(Spendable(balance, network.contract.for_address(address),
                                   tx_id_b, idx))

    txn_fee = estimate_p2pkh_tx_bytes(len(tx_ins), 3) * recommend_satoshi_per_byte() / 3

    _txs_out = [TxOut(total_bal - txn_fee - MIN_BTC_OUT, network.contract.for_address(change_address)),
                TxOut(0, binascii.unhexlify(omni_tether_script(send_amount))),
                TxOut(MIN_BTC_OUT, network.contract.for_address(receiver))]

    version, lock_time = 1, 0
    tx = Tx(version, _txs_in, _txs_out, lock_time)
    tx.set_unspents(_un_spent)

    # construct hash160_lookup[hash160] = (secret_exponent, public_pair, compressed) for each individual key
    hash160_lookup = build_hash160_lookup([network.parse.wif(wif_key).secret_exponent() for wif_key in wif_keys],
                                          [secp256k1_generator])

    for i in range(0, len(tx_ins)):
        if tx_ins[i][-1]:
            p2sh_lookup = build_p2sh_lookup([binascii.unhexlify(tx_ins[i][-1])])
        else:
            p2sh_lookup = None

        r = BitcoinSolver(tx).solve(hash160_lookup, i, hash_type=SIGHASH_ALL, p2sh_lookup=p2sh_lookup)
        if isinstance(r, bytes):
            tx.txs_in[i].script = r
        else:
            tx.txs_in[i].script = r[0]
            tx.set_witness(i, r[1])

    return tx.as_hex(), tx.id()


if __name__ == '__main__':
    from decimal import Decimal
    from btc_sample import get_utxo, broadcast_raw

    # (utxo id, utxo index, balance in satoshi, sender address)
    # tx_ins = [('xx', 1, 284538, 'xx'),
    #           ('xx', 0, 28478, 'xx'),
    #           ]
    # keys = ['hex key1',
    #         'hex key2']
    # raw_hex, tx_id = tether_tx(tx_ins,
    #                            keys,
    #                            int(Decimal('0.5') * Decimal(10 ** 8)),
    #                            'address to receive usdt',
    #                            'address to receive left btc')
    #
    # print('signed raw hex:')
    # print(raw_hex)
    # print('txn id/hash:')
    # print(tx_id)
    #
    # print(broadcast_raw(raw_hex))
