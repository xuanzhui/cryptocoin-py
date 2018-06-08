# -*- coding: utf-8 -*-
"""
has dependency of pycoin
check https://github.com/richardkiss/pycoin
pip install pycoin

usdt transaction is based on btc p2pkh transaction with OP_RETURN
"""

import binascii
from pycoin.tx.Tx import Tx, SIGHASH_ALL
from pycoin.tx.TxIn import TxIn
from pycoin.tx.TxOut import TxOut
from pycoin.tx.Spendable import Spendable
from pycoin.ui import standard_tx_out_script
from pycoin.tx.pay_to import build_hash160_lookup
from pycoin.serialize import h2b_rev
from btc_sample import estimate_p2pkh_tx_bytes
from btc_sample import recommend_satoshi_per_byte


def tether_tx(tx_ins, private_key, send_amount, receiver):
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
    """
    _txs_in = []
    _un_spent = []
    total_bal = 0

    for tx_id, idx, balance, address in tx_ins:
        total_bal += balance

        # must h2b_rev NOT h2b
        tx_id_b = h2b_rev(tx_id)
        _txs_in.append(TxIn(tx_id_b, idx))

        _un_spent.append(Spendable(balance, standard_tx_out_script(address), tx_id_b, idx))

    txn_fee = estimate_p2pkh_tx_bytes(len(tx_ins), 3) * recommend_satoshi_per_byte()

    _txs_out = [TxOut(total_bal - txn_fee - 546, standard_tx_out_script(tx_ins[0][3])),
                TxOut(0, binascii.unhexlify(omni_tether_script(send_amount))),
                TxOut(546, standard_tx_out_script(receiver))]

    version, lock_time = 1, 0
    tx = Tx(version, _txs_in, _txs_out, lock_time)
    tx.set_unspents(_un_spent)

    solver = build_hash160_lookup([int(private_key, 16)] * len(tx_ins))
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


if __name__ == '__main__':
    from decimal import Decimal

    # (utxo id, utxo index, balance in satoshi, sender address)
    tx_ins = [('===> utxo id', 1, 1489720,
               '===> sender address')]

    raw_hex, tx_id = tether_tx(tx_ins,
                               '===> private key hex format',
                               int(Decimal('0.1') * Decimal(10 ** 8)),
                               '===> receiver address')

    print('signed raw hex:')
    print(raw_hex)
    print('txn id/hash:')
    print(tx_id)
