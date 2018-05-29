# -*- coding: utf-8 -*-
"""
hierarchical deterministic, combine bip32 bip39 bip43 bip44

has dependency of pycoin, mnemonic
for simplified chinese support, you may would like to check fork
https://github.com/xuanzhui/python-mnemonic
"""

from pycoin.key.BIP32Node import BIP32Node
import binascii
from mnemonic import Mnemonic

"""
The following table describes the relation between the initial entropy length (ENT),
the checksum length (CS) and the length of the generated mnemonic sentence (MS) in words.
CS = ENT / 32
MS = (ENT + CS) / 11
|  ENT  | CS | ENT+CS |  MS  |
+-------+----+--------+------+
|  128  |  4 |   132  |  12  |
|  160  |  5 |   165  |  15  |
|  192  |  6 |   198  |  18  |
|  224  |  7 |   231  |  21  |
|  256  |  8 |   264  |  24  |
"""
MS_ENT = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}


def generate_mnemonic(word_count=12, language='english'):
    """
    generate mnemonic sentence
    :param word_count: 12, 15, 18, 21, 24
    :param language: can be english or chinese_simplified
    """
    if word_count not in MS_ENT.keys():
        raise ValueError('invalid word count')

    mm = Mnemonic(language)
    return mm.generate(MS_ENT[word_count])


def mnemonic_to_hex_seed(mnemonic, passphrase=''):
    """
    mnemonic sentence to hex format, the result(unhexlify) can be used by bip32 node
    :param mnemonic: mnemonic sentence
    :param passphrase: used for PBKDF2 salt('mnemonic' + passphrase)
    """
    master_seed = Mnemonic.to_seed(mnemonic, passphrase=passphrase)
    return binascii.hexlify(master_seed).decode()


def mnemonic_to_bip32_node(mnemonic, passphrase='', netcode='BTC'):
    """
    mnemonic sentence to bip32 node
    :param mnemonic: mnemonic sentence
    :param passphrase: used for PBKDF2 salt('mnemonic' + passphrase)
    :param netcode: 'BTC' => "mainnet", 'XTN' => "testnet3"
    """
    master_seed = Mnemonic.to_seed(mnemonic, passphrase=passphrase)
    return BIP32Node.from_master_secret(master_seed, netcode=netcode)


def mnemonic_to_bip32_hwif(mnemonic, passphrase='', netcode='BTC'):
    """
    mnemonic sentence to bip32 private key format which starts with 'xprv'
    :param mnemonic: mnemonic sentence
    :param passphrase: used for PBKDF2 salt('mnemonic' + passphrase)
    :param netcode: 'BTC' => "mainnet", 'XTN' => "testnet3"
    """
    master_seed = Mnemonic.to_seed(mnemonic, passphrase=passphrase)
    master = BIP32Node.from_master_secret(master_seed, netcode=netcode)
    return master.hwif(as_private=True)


def bip44_btc_account(mnemonic, account=0, passphrase=''):
    """
    bip44 btc format m / 44' / 0' / {account}'
    account can generate related address/key pairs
    :param mnemonic: mnemonic sentence
    :param account: 0 as first account
    :param passphrase: used for PBKDF2 salt('mnemonic' + passphrase)
    """
    master_seed = Mnemonic.to_seed(mnemonic, passphrase=passphrase)
    master = BIP32Node.from_master_secret(master_seed)
    return master.subkey_for_path(f'44H/0H/{account}H')


def bip44_eth_account(mnemonic, account=0, passphrase=''):
    """
    bip44 eth format m / 44' / 0' / {account}'
    account can generate related address/key pairs
    :param mnemonic: mnemonic sentence
    :param account: 0 as first account
    :param passphrase: used for PBKDF2 salt('mnemonic' + passphrase)
    """
    master_seed = Mnemonic.to_seed(mnemonic, passphrase=passphrase)
    master = BIP32Node.from_master_secret(master_seed)
    return master.subkey_for_path(f'44H/60H/{account}H')


def bip44_test_account(mnemonic, account=0, passphrase=''):
    """
    bip44 testnet format m / 44' / 1' / {account}'
    account can generate related address/key pairs
    :param mnemonic: mnemonic sentence
    :param account: 0 as first account
    :param passphrase: used for PBKDF2 salt('mnemonic' + passphrase)
    """
    master_seed = Mnemonic.to_seed(mnemonic, passphrase=passphrase)
    master = BIP32Node.from_master_secret(master_seed, netcode='XTN')
    return master.subkey_for_path(f'44H/1H/{account}H')


def bip44_btc_external_key(mnemonic, account=0, key_idx=0, passphrase=''):
    """
    bip44 btc format m / 44' / 0' / {account}' / 0 / {key_idx}
    :param mnemonic: mnemonic sentence
    :param account: 0 as first account
    :param key_idx: 0 as first key
    :param passphrase: used for PBKDF2 salt('mnemonic' + passphrase)
    """
    master_seed = Mnemonic.to_seed(mnemonic, passphrase=passphrase)
    master = BIP32Node.from_master_secret(master_seed)
    return master.subkey_for_path(f'44H/0H/{account}H/0/{key_idx}')


def bip44_eth_external_key(mnemonic, account=0, key_idx=0, passphrase=''):
    """
    bip44 eth format m / 44' / 60' / {account}' / 0 / {key_idx}
    :param mnemonic: mnemonic sentence
    :param account: 0 as first account
    :param key_idx: 0 as first key
    :param passphrase: used for PBKDF2 salt('mnemonic' + passphrase)
    """
    master_seed = Mnemonic.to_seed(mnemonic, passphrase=passphrase)
    master = BIP32Node.from_master_secret(master_seed)
    return master.subkey_for_path(f'44H/60H/{account}H/0/{key_idx}')


def bip44_test_external_key(mnemonic, account=0, key_idx=0, passphrase=''):
    """
    bip44 testnet format m / 44' / 0' / {account}' / 0 / {key_idx}
    :param mnemonic: mnemonic sentence
    :param account: 0 as first account
    :param key_idx: 0 as first key
    :param passphrase: used for PBKDF2 salt('mnemonic' + passphrase)
    """
    master_seed = Mnemonic.to_seed(mnemonic, passphrase=passphrase)
    master = BIP32Node.from_master_secret(master_seed, netcode='XTN')
    return master.subkey_for_path(f'44H/1H/{account}H/0/{key_idx}')


def external_key_from_account(account, key_idx=0):
    return account.subkey_for_path(f'0/{key_idx}')


def external_key_from_account_hwif(hwif, key_idx=0):
    """
    path 0 / {key_idx}
    :param hwif: bip32 private key format
    :param key_idx: 0 as first key
    """
    node = BIP32Node.from_hwif(hwif)
    return node.subkey_for_path(f'0/{key_idx}')


if __name__ == '__main__':
    print('================ key point is to generate private key ================')
    print('================ high-level bip32 node has full control of lower-level/child nodes ================')

    # https://iancoleman.io/bip39 is a good place to check result

    print('================ btc ================')
    seed_str = generate_mnemonic(15)
    print('english mnemonic sentence:', seed_str)

    print('bip39 seed:', mnemonic_to_hex_seed(seed_str))
    print('bip32 root:', mnemonic_to_bip32_hwif(seed_str))

    master = mnemonic_to_bip32_node(seed_str)
    account2_key1 = master.subkey_for_path('44H/0H/2H/0/1')
    print('account2 address1:', account2_key1.address(use_uncompressed=False))
    print('account2 address1 private key:', account2_key1.wif())

    account2 = bip44_btc_account(seed_str, account=2)
    account2_hwif = account2.hwif(as_private=True)
    print('account2 extended private key:', account2_hwif)

    account2_key1_1 = external_key_from_account_hwif(account2_hwif, key_idx=1)
    print('account2 address1:', account2_key1_1.address(use_uncompressed=False))
    print('account2 address1 private key:', account2_key1_1.wif())

    print('================ eth ================')
    ch_seed_str = generate_mnemonic(15, language='chinese_simplified')
    print('chinese mnemonic sentence:', ch_seed_str)
    print('bip32 root:', mnemonic_to_bip32_hwif(ch_seed_str, passphrase='开心'))

    eth_acc3 = bip44_eth_account(ch_seed_str, account=3, passphrase='开心')
    eth_acc3_key2 = external_key_from_account(eth_acc3, key_idx=2)
    pri_key = eth_acc3_key2.secret_exponent()

    import web3
    print('private hex:', hex(pri_key))
    real_acc = web3.Account.privateKeyToAccount(pri_key)
    print('eth address:', real_acc.address)
    print('private key:', '0x' + binascii.hexlify(real_acc.privateKey).decode())

    print('================ testnet ================')
    print('bip32 root:', mnemonic_to_bip32_hwif(ch_seed_str, passphrase='开心', netcode='XTN'))
    test_account2_key1 = bip44_test_external_key(ch_seed_str, account=3, key_idx=2, passphrase='开心')
    print('account2 address1:', test_account2_key1.address(use_uncompressed=False))
    print('account2 address1 private key:', test_account2_key1.wif())
