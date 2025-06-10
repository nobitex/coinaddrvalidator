"""
:mod:`coinaddr.currency`
~~~~~~~~~~~~~~~~~~~~~~~~

Containers for holding all the necessary data for validating cryptocurrencies.
"""

import attr
from typing import Dict, Any, Optional

from .interfaces import ICurrency, INamedInstanceContainer
from .base import NamedInstanceContainerBase


class Currencies(metaclass=NamedInstanceContainerBase):
    """Container for all currencies."""

    @classmethod
    def get(cls, name: str, default: Any = None) -> Any:
        """Return currency object with matching name or ticker."""
        for inst in cls.instances.values():
            if name in (inst.name, inst.ticker):
                return inst
        else:
            return default


class CurrencyMeta(type):
    """Register currency classes on Currencies.currencies."""

    def __call__(cls, *args: Any, **kwargs: Any) -> Any:
        inst = super(CurrencyMeta, cls).__call__(*args, **kwargs)
        Currencies[inst.name] = inst
        return inst


@attr.s(frozen=True, slots=True, cmp=False)
class Currency(metaclass=CurrencyMeta):
    """An immutable representation of a cryptocurrency specification."""

    name = attr.ib(validator=attr.validators.instance_of(str))
    ticker = attr.ib(validator=attr.validators.instance_of(str))
    validator = attr.ib(validator=attr.validators.instance_of(str))
    networks = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(dict)),
        default=attr.Factory(dict))
    address_types = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(dict)),
        default=attr.Factory(dict))
    charset = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(bytes)),
        default=None)


Currency('bitcoin', ticker='btc', validator='BitcoinBasedCheck',
         networks=dict(
             main=(0x00, 0x05, 0x0488b21e, 0x049d7cb2, 0x04b24746, 0x0295b43f,
                   0x02aa7ed3, 'bc'),
             test=(0x6f, 0xc4, 0x043587cf, 0x044a5262, 0x045f1cf6, 0x024289ef,
                   0x02575483, 'tb')))
Currency('bitcoin-sv', ticker='bsv', validator='Base58Check',
         networks=dict(
             main=(0x00, 0x05, 0x0488b21e, 0x049d7cb2, 0x04b24746, 0x0295b43f,
                   0x02aa7ed3),
             test=(0x6f, 0xc4, 0x043587cf, 0x044a5262, 0x045f1cf6, 0x024289ef,
                   0x02575483)))
Currency('bitcoin-cash', ticker='bch', validator='Base58Check',
         networks=dict(
             main=(0x00, 0x05), test=(0x6f, 0xc4)))
Currency('litecoin', ticker='ltc', validator='BitcoinBasedCheck',
         networks=dict(
             main=(0x30, 0x05, 0x32, 0x019da462, 0x01b26ef6,
                   0x488B21E, 0x49D7CB2, 0x4B24746, 0x295B43F,
                   0x2AA7ED3, 'ltc'),
             test=(0x6f, 0xc4, 0x0436f6e1, 'tltc')))
Currency('dogecoin', ticker='doge', validator='Base58Check',
         networks=dict(
             main=(0x1e, 0x16), test=(0x71, 0xc4)))
Currency('dashcoin', ticker='dash', validator='Base58Check',
         networks=dict(
             main=(0x4c, 0x10), test=(0x8c, 0x13)))
Currency('neocoin', ticker='neo', validator='Base58Check',
         networks=dict(both=(0x17,)))
Currency('ripple', ticker='xrp', validator='Base58Check',
         networks=dict(both=(0x00, 0x05)),
         charset=(b'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcd'
                  b'eCg65jkm8oFqi1tuvAxyz'))
Currency('ethereum', ticker='eth', validator='Ethereum')
Currency('ether-zero', ticker='etz', validator='Ethereum')
Currency('ethereum-classic', ticker='etc', validator='Ethereum')
Currency('xdai', ticker='stake', validator='Ethereum')

Currency('zcash', ticker='zec', validator='Base58Check',
         networks=dict(
             main=(0x1cb8, 0x1cbd), test=(0x1d25, 0x1cba)))
Currency('tezos', ticker='xtz', validator='Base58Check',
         networks=dict(
             both=(0x06a19f, 0x06a1a1, 0x06a1a4, 0x25a79)),
         address_types=dict(
             originated_account=(0x025a79,),
             implicit_account=(0x06a19f, 0x06a1a1, 0x06a1a4,)))
Currency('horizen', ticker='zen', validator='Base58Check',
         networks=dict(
             both=(0x2089, 0x1cb8)))
Currency('eos', ticker='eos', validator='EOS')
Currency('stellar', ticker='xlm', validator='Stellar')
Currency('ravencoin', ticker='rvn', validator='Base58Check',
         networks=dict(
             main=(0x3c, 0x0488B21E), test=(0x6f, 0x043587CF)))
Currency('tronix', ticker='trx', validator='Base58Check',
         networks=dict(
             main=(0x41,), test=(0xa0,)))
Currency('decred', ticker='dcr', validator='DecredCheck',
         networks=dict(
             main=(0x073f, 0x071a, 0x02fda926),
             test=(0x0f21, 0x0efc, 0x043587d1)),
         address_types=dict(
             address=(0x073f, 0x0f21), ticket=(0x071a, 0x0efc),
             xpubkey=(0x02fda926, 0x043587d1)))
Currency('cardano', ticker='ada', validator='CardanoCheck',
         networks=dict(
             main=(0x82D818584283581C,), test=(0x82D818582883581C,)))

Currency('cosmos', ticker='atom', validator='CosmosCheck')

Currency('binancecoin', ticker='bnb', validator='Bech32Check',
         networks=dict(
             main=("bnb",), test=("tbnb",)))

Currency('groestlcoin', ticker='grs', validator='GRSCheck',
         networks=dict(
             main=('F', '3'), test=('m', 'n')))

Currency('ontology', ticker='ont', validator='Base58Check',
         networks=dict(
             both=(0x17,)))
Currency('boscoin', ticker='bos', validator='Stellar')
Currency('vechain', ticker='vet', validator='Ethereum')
Currency('terramoney', ticker='luna', validator='TerraMoney')
Currency('polkadot', ticker='dot', validator='PolkadotCheck')
Currency('kusama', ticker='ksm', validator='KusamaCheck')
