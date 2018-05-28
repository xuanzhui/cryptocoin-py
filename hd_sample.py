# -*- coding: utf-8 -*-
"""
has dependency of pycoin
hierarchical deterministic, combine bip32 bip39 bip43 bip44
"""

from pycoin.ecdsa.secp256k1 import generator_secp256k1
from pycoin.serialize import h2b
from pycoin.key.BIP32Node import BIP32Node
import binascii
import hmac
import hashlib
from mnemonic import Mnemonic

mm = Mnemonic('chinese_simplified')
print(mm.list_languages())
seed_str = mm.generate(160)
print(seed_str)
master_seed = Mnemonic.to_seed('申 丹 畅 刷 署 坡 阀 医 益 族 章 归 役 霞 钉', passphrase='哈哈')
seed_hex = binascii.hexlify(master_seed)
print(seed_hex)

master = BIP32Node.from_master_secret(master_seed)
print(master.hwif(as_private=True))

sub = master.subkey_for_path("44H/0H/0H/0/1")
print(sub.address(use_uncompressed=False))
sub_key = sub.wif()
print(sub_key)


'''
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
'''
