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
from pycoin.solve.utils import build_hash160_lookup, build_p2sh_lookup
from pycoin.encoding.hexbytes import h2b_rev
from btc_sample import estimate_p2pkh_tx_bytes
from btc_sample import recommend_satoshi_per_byte
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from pycoin.networks.registry import network_for_netcode
network = network_for_netcode("BTC")


def tether_tx(tx_ins, private_key, send_amount, receiver, satoshi_per_byte=None):
    """
    simple usdt transaction
    here assume utxo comes from the sender and is used for mine fee
    bitcoin change will be sent back to sender address

    of course different address's utxo can be used for mine fee,
    but should be aware sender is determined by the first input in the tx
    bitcoin change can also be sent back to different address,
    but should be aware receiver is indicated by the last output address that is not the sender

    for full customization, use btc sample p2pkh_tx
    :param tx_ins: utxo from the sender
    :param private_key: private key of the same sender
    :param send_amount: (display amount) * (10 ** 8)
    :param receiver: address to receive usdt
    :param satoshi_per_byte: miner fee
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

    if not satoshi_per_byte:
        satoshi_per_byte = recommend_satoshi_per_byte()

    txn_fee = estimate_p2pkh_tx_bytes(len(tx_ins), 3) * satoshi_per_byte

    _txs_out = [TxOut(total_bal - txn_fee - 546, network.contract.for_address(tx_ins[0][3])),
                TxOut(0, binascii.unhexlify(omni_tether_script(send_amount))),
                TxOut(546, network.contract.for_address(receiver))]

    version, lock_time = 1, 0
    tx = Tx(version, _txs_in, _txs_out, lock_time)
    tx.set_unspents(_un_spent)

    solver = build_hash160_lookup([int(private_key, 16)] * len(tx_ins), [secp256k1_generator])
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


# def tether_tx_sh(tx_ins, wif_keys, send_amount, receiver, change_address):
#     """
#     spend usdt having p2sh utxo
#     :param tx_ins: list with tuple(tx_id, idx, balance, address, redeem_script),
#         redeem_script is required for p2sh utxo, set it None for p2pkh utxo
#     :param wif_keys: private keys of the inputs
#     :param send_amount: (display amount) * (10 ** 8)
#     :param receiver: address to receive usdt
#     :param change_address: address to receive btc change
#     """
#     _txs_in = []
#     _un_spent = []
#     total_bal = 0
#
#     for tx_id, idx, balance, address, _ in tx_ins:
#         total_bal += balance
#
#         # must h2b_rev NOT h2b
#         tx_id_b = h2b_rev(tx_id)
#         _txs_in.append(TxIn(tx_id_b, idx))
#
#         _un_spent.append(Spendable(balance, script_obj_from_address(address, netcodes=['BTC']).script(), tx_id_b, idx))
#
#     txn_fee = estimate_p2pkh_tx_bytes(len(tx_ins), 3) * recommend_satoshi_per_byte()
#
#     _txs_out = [TxOut(total_bal - txn_fee - 546, script_obj_from_address(change_address).script()),
#                 TxOut(0, binascii.unhexlify(omni_tether_script(send_amount))),
#                 TxOut(546, script_obj_from_address(receiver).script())]
#
#     version, lock_time = 1, 0
#     tx = Tx(version, _txs_in, _txs_out, lock_time)
#     tx.set_unspents(_un_spent)
#
#     # construct hash160_lookup[hash160] = (secret_exponent, public_pair, compressed) for each individual key
#     hash160_lookup = build_hash160_lookup([Key.from_text(wif_key).secret_exponent() for wif_key in wif_keys])
#
#     for i in range(0, len(tx_ins)):
#         if tx_ins[i][-1]:
#             # p2sh_lookup = build_p2sh_lookup([binascii.unhexlify(tx_ins[i][-1])])
#             # tx.sign_tx_in(hash160_lookup, i, tx.unspents[i].script, hash_type=SIGHASH_ALL, p2sh_lookup=p2sh_lookup)
#             u_key = Key(secret_exponent=int('bd46417c531c36629aec7ded3c6c7ecd0acace098f47c6b9d82b77728fb477f5', 16),
#                         prefer_uncompressed=False, netcode='BTC')
#             tx.txs_in[i].script = u_key.sec()
#         else:
#             tx.sign_tx_in(hash160_lookup, i, tx.unspents[i].script, hash_type=SIGHASH_ALL)
#
#     return tx.as_hex(), tx.id()


if __name__ == '__main__':
    from decimal import Decimal
    from btc_sample import get_utxo, broadcast_raw
    import time

    # (utxo id, utxo index, balance in satoshi, sender address)
    # tx_ins = [('xx', 1, 284538,
    #            'xx'),
    #           ]
    #
    # raw_hex, tx_id = tether_tx(tx_ins,
    #                            'xx',
    #                            int(Decimal('0.5') * Decimal(10 ** 8)),
    #                            'xx')
    #
    # print('signed raw hex:')
    # print(raw_hex)
    # print('txn id/hash:')
    # print(tx_id)
    #
    # print(broadcast_raw(raw_hex))

    # from pycoin.tx.pay_to import ScriptPayToScript
    # from pycoin.key import Key
    #
    # u_key = Key(secret_exponent=int('bd46417c531c36629aec7ded3c6c7ecd0acace098f47c6b9d82b77728fb477f5', 16),
    #             prefer_uncompressed=False, netcode='BTC')
    # u_wif = u_key.wif()
    #
    # script = ScriptPayToScript(u_key.hash160())
    # # print(script.address())
    # redeem = binascii.hexlify(script.script()).decode()
    # print(binascii.hexlify(u_key.sec()))
    #
    # b_key = Key(secret_exponent=int('9e50b3e179eda7d988db33919ebac1464710de58cae1862c3e853c90692e3e76', 16),
    #             prefer_uncompressed=False, netcode='BTC')
    # b_wif = b_key.wif()
    # # print(b_key.address())
    # # print(b_wif)
    #
    # tx_ins = [('90c54d534ba78b30f2bb2dd0adb38cc7fbe48e8ce429068dc2135a69740f8067', 2, 540,
    #            '3Kuqjvvz81aRdiYnSJHSx5re2cCh1z3qfW', binascii.hexlify(u_key.sec())),
    #           ('95fee62879f768184254f5775352d4743460223ae269547c03a215ed6656b74f', 0, 139986,
    #            '1PYQsxk5GoWc3bL9TQMQwpvnHWa6btetUK', None)
    #           ]
    # in_keys = [u_wif,
    #            b_wif
    #            ]
    #
    # raw_hex, tx_id = tether_tx_sh(tx_ins,
    #                               in_keys,
    #                               int(Decimal('0.1') * Decimal(10 ** 8)),
    #                               '17LNm71xoEvF5h3KuqhcNAsCnPnFSDWUJT',
    #                               '1PYQsxk5GoWc3bL9TQMQwpvnHWa6btetUK')
    # print('signed raw hex:')
    # print(raw_hex)
    # print('txn id/hash:')
    # print(tx_id)
