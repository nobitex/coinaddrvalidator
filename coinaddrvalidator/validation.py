"""
:mod:`coinaddr.validation`
~~~~~~~~~~~~~~~~~~~~~~~~

Validation of cryptocurrency addresses.
"""

import re
from hashlib import sha256, blake2b
import functools
import operator
from typing import Any, Dict, Optional, Type, ClassVar, Union

import attr
from Crypto.Hash import keccak
import base58check
import math
from binascii import unhexlify, crc32
import base64
from blake256 import blake256
import cbor
import bech32
import groestlcoin_hash2

from .encoding import crc16
from .interfaces import (
    ICurrency, IValidator, IValidationRequest, IValidationResult)
from .currency import Currencies, Currency
from .base import NamedSubclassContainerBase


class Validators(metaclass=NamedSubclassContainerBase):
    """Container for all validators."""


class ValidatorMeta(type):
    """Register validator classes on Validators.validators."""

    def __new__(mcs, cls, bases, attrs):
        new = type.__new__(mcs, cls, bases, attrs)
        if new.name:
            Validators[new.name] = new
        return new


@attr.s(frozen=True, slots=True)
class ValidationResult:
    """Represents all data for a validation result."""

    name = attr.ib(validator=attr.validators.instance_of(str))
    ticker = attr.ib(validator=attr.validators.instance_of(str))
    address = attr.ib(validator=attr.validators.instance_of((str, bytes)))
    valid = attr.ib(validator=attr.validators.instance_of(bool))
    network = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(str)), default=None)
    is_extended = attr.ib(validator=attr.validators.instance_of(bool), default=False)
    address_type = attr.ib(validator=attr.validators.instance_of(str), default='address')

    def __bool__(self):
        return self.valid


@attr.s(frozen=True, slots=True)
class ValidationRequest:
    """Contains the data and helpers for a given validation request."""

    currency = attr.ib(validator=attr.validators.instance_of((str, Currency)))
    address = attr.ib(validator=attr.validators.instance_of(str))
    extras = attr.ib(validator=attr.validators.instance_of(dict), default=attr.Factory(dict))
    networks = attr.ib(validator=attr.validators.instance_of(str), default='')

    def execute(self) -> ValidationResult:
        """Executes the request and returns a ValidationResult object"""
        if isinstance(self.currency, str):
            currency = Currencies.get(self.currency)
            if not currency:
                return ValidationResult(
                    name=self.currency,
                    ticker=self.currency,
                    address=self.address.encode('utf-8'),
                    valid=False)
        else:
            currency = self.currency

        validator_cls = self._get_validator_cls(currency.validator)
        if not validator_cls:
            return ValidationResult(
                name=currency.name,
                ticker=currency.ticker,
                address=self.address.encode('utf-8'),
                valid=False)

        # Create a new request with the original string address
        request = ValidationRequest(
            currency=currency,
            address=self.address,
            extras=self.extras,
            networks=self.networks
        )

        validator = validator_cls(request=request)

        valid = False
        network = ''
        is_extended = False
        address_type = 'address'
        try:
            valid = validator.validate()
            network = validator.network
            is_extended = validator.validate_extended()
            address_type = validator.address_type
        except:
            pass

        return ValidationResult(
            name=currency.name,
            ticker=currency.ticker,
            address=self.address.encode('utf-8'),
            valid=valid,
            network=network,
            is_extended=is_extended,
            address_type=address_type)

    def _get_validator_cls(self, validator_name: str) -> Optional[Type[IValidator]]:
        """Get the validator class for the given validator name."""
        return Validators.get(validator_name)


@attr.s(cmp=False, slots=True)
class ValidatorBase(metaclass=ValidatorMeta):
    """Validator Interface."""

    name: ClassVar[str] = None

    request = attr.ib(
        validator=attr.validators.instance_of(ValidationRequest)
    )

    def validate(self) -> bool:
        """Validate the address type, return True if valid, else False."""
        raise NotImplementedError

    def validate_extended(self) -> bool:
        """Validate the extended keys, return True if valid, else False."""
        raise NotImplementedError

    @property
    def network(self) -> str:
        """Return the network derived from the network version bytes."""
        raise NotImplementedError

    @property
    def address_type(self) -> str:
        """Return the address type derived from the network version bytes."""
        return 'address'


@attr.s(frozen=True, slots=True, cmp=False)
class GRSValidator(ValidatorBase):
    """Validates Groestlcoin addresses."""

    name = 'GRSCheck'

    def validate(self) -> bool:
        # groestlcoin address is 34 bytes long
        if len(self.request.address) != 34:
            return False
        try:
            decoded = base58check.b58decode(self.request.address)
        except ValueError:
            return False

        hash_str = decoded[0:21]
        checksum = groestlcoin_hash2.groestl_hash(hash_str)[:4]
        expected_checksum = decoded[21:]

        if checksum != expected_checksum:
            return False

        return True

    def validate_extended(self) -> bool:
        return False

    @property
    def network(self) -> str:
        for name, networks in self.request.currency.networks.items():
            for netw in networks:
                if self.request.address.startswith(netw.encode('utf-8')):
                    return name
        return ""


@attr.s(frozen=True, slots=True, cmp=False)
class Bech32CheckValidator(ValidatorBase):
    """Validates Bech32 addresses."""

    name = 'Bech32Check'

    def validate(self) -> bool:
        decoded_address = bech32.bech32_decode(self.request.address.decode('utf-8'))
        data = decoded_address[1]

        if self.network == "":
            return False

        if data is None:
            return False

        return True

    def validate_extended(self) -> bool:
        return False

    @property
    def network(self) -> str:
        decoded_address = bech32.bech32_decode(self.request.address.decode('utf-8'))
        hrp = decoded_address[0]

        for name, networks in self.request.currency.networks.items():
            for netw in networks:
                if hrp == netw:
                    return name
        return ""


@attr.s(frozen=True, slots=True, cmp=False)
class Base58CheckValidator(ValidatorBase):
    """Validates Base58Check based cryptocurrency addresses."""

    name = 'Base58Check'
    # base58 alphabet representation
    dec_digit_to_base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    base58_digit_to_dec = {b58: dec for dec, b58 in enumerate(dec_digit_to_base58)}

    def validate(self) -> bool:
        """extended keys have their own validation"""
        if len(self.request.address) == 111:
            return self.validate_extended()

        """Validate the address."""
        if 25 > len(self.request.address) > 35:
            return False

        try:
            # Use custom charset if provided
            extras = self.request.extras.copy()
            if self.request.currency.charset:
                extras['charset'] = self.request.currency.charset
            abytes = base58check.b58decode(
                self.request.address, **extras)
        except ValueError:
            return False

        # For XRP, we need to check the network first
        network = self.network
        if network == '':
            return False

        # Calculate checksum
        checksum = sha256(sha256(abytes[:-4]).digest()).digest()[:4]
        if abytes[-4:] != checksum:
            return False

        # Verify the address can be re-encoded correctly
        try:
            reencoded = base58check.b58encode(abytes, **extras)
            return self.request.address == reencoded.decode('utf-8')
        except Exception:
            return False

    def validate_extended(self, checksum_algo='sha256') -> bool:
        if len(self.request.address) != 111:
            return False

        if self.network == '':
            return False

        # strip leading "zeros" (the "1" digit with base58)
        base58_stripped = self.request.address.lstrip("1")
        # convert base58 to decimal
        int_rep = 0
        for base58_digit in base58_stripped:
            int_rep *= 58
            try:
                int_rep += self.base58_digit_to_dec[base58_digit]
            except KeyError:
                # not a valid base58 digit -> invalid address
                return False

        # encode it to base64
        hex_rep = "{:X}".format(int_rep)
        # if the length is odd, add leading zero (needed for b16decode)
        if len(hex_rep) % 2 == 1:
            hex_rep = "0" + hex_rep
        # decode it into a binary string, padded with zeros
        # 72 bytes (extended key size) + 4 bytes (prefix version bytes)
        all_bytes = base64.b16decode(hex_rep).rjust(82, b"\0")

        # count leading zeros
        zero_count = next(zeros for zeros, byte in enumerate(all_bytes) if byte != 0)
        # compare it with the number of leading zeros lstripped at the beginning
        if len(self.request.address) - len(base58_stripped) != zero_count:
            return False

        if checksum_algo == 'blake256':
            checksum = blake256.blake_hash(blake256.blake_hash(all_bytes[:-4]))[:4]
        elif checksum_algo == 'sha256':
            checksum = sha256(sha256(all_bytes[:-4]).digest()).digest()[:4]
        else:
            return False

        # checking if the checksum is valid
        if checksum != all_bytes[-4:]:
            return False

        return True

    @property
    def network(self) -> str:
        """Return network derived from network version bytes."""
        try:
            # Use custom charset if provided
            extras = self.request.extras.copy()
            if self.request.currency.charset:
                extras['charset'] = self.request.currency.charset
            abytes = base58check.b58decode(
                self.request.address, **extras)
        except ValueError:
            return ''

        nbyte = abytes[0]
        for name, networks in self.request.currency.networks.items():
            if isinstance(networks, tuple):
                if nbyte in networks:
                    return name
            elif isinstance(networks, str):
                if self.request.address.startswith(networks):
                    return name
        return ''

    @property
    def address_type(self) -> str:
        """Return address type derived from network version bytes."""
        if len(self.request.address) == 0:
            return ''
        try:
            # Use custom charset if provided
            extras = self.request.extras.copy()
            if self.request.currency.charset:
                extras['charset'] = self.request.currency.charset
            abytes = base58check.b58decode(
                self.request.address, **extras)
        except ValueError:
            return ''

        for name, networks in self.request.currency.address_types.items():
            for netw in networks:
                if netw != 0:
                    # count the prefix length in bytes
                    prefixlen = math.ceil(math.floor((math.log(netw) / math.log(2)) + 1) / 8)
                else:
                    prefixlen = 1
                address_prefix = [x for x in bytearray(abytes[:prefixlen])]
                if prefixtodec(address_prefix) == netw:
                    return name

        if len(self.request.currency.address_types.items()) == 0:
            return 'address'
        else:
            return ''


@attr.s(frozen=True, slots=True, cmp=False)
class EthereumValidator(ValidatorBase):
    """Validates ethereum based cryptocurrency addresses."""

    name = 'Ethereum'
    non_checksummed_patterns = (
        re.compile("^(0x)?[0-9a-f]{40}$"), re.compile("^(0x)?[0-9A-F]{40}$")
    )

    def validate(self) -> bool:
        """Validate the address."""
        address = self.request.address

        # Remove '0x' prefix if present
        if address.startswith('0x'):
            address = address[2:]

        # Check if it's a non-checksummed address
        if any(bool(pat.match(address)) for pat in self.non_checksummed_patterns):
            return True

        # Ethereum address has to contain exactly 40 chars (20-bytes)
        if len(address) != 40:
            return False

        # Ethereum address is generated by keccak algorithm and has to be hexadecimal
        k = keccak.new(digest_bits=256)
        addr_hash = k.update(address.lower().encode('ascii')).hexdigest()
        
        # Check each character against the hash
        for i, letter in enumerate(address):
            if any([
                int(addr_hash[i], 16) >= 8 and letter.upper() != letter,
                int(addr_hash[i], 16) < 8 and letter.lower() != letter
            ]):
                return False
        return True

    def validate_extended(self) -> bool:
        return False

    @property
    def network(self) -> str:
        """Return network derived from network version bytes."""
        return 'both'


@attr.s(frozen=True, slots=True, cmp=False)
class EosValidator(ValidatorBase):
    """Validates EOS cryptocurrency addresses."""

    name = 'EOS'

    def validate(self) -> bool:
        """Validate the address."""
        address = self.request.address

        # EOS addresses must be 12 characters long
        if len(address) != 12:
            return False

        # EOS addresses must start with a letter and contain only a-z, 1-5, and .
        eos_pattern = re.compile('^[a-z][a-z1-5.]{10}[a-z1-5]$')
        return bool(eos_pattern.match(address))

    def validate_extended(self) -> bool:
        return False

    @property
    def network(self) -> str:
        return ''

    @property
    def address_type(self) -> str:
        return 'address'


@attr.s(frozen=True, slots=True, cmp=False)
class StellarValidator(ValidatorBase):
    """Validates Stellar cryptocurrency addresses."""

    name = 'Stellar'

    def validate(self) -> bool:
        try:
            decoded_address = base64.b32decode(self.request.address)
        except:
            return False

        version_byte = decoded_address[0]
        payload = decoded_address[0:-2]
        expected_checksum = int.from_bytes(decoded_address[-2:], byteorder='little')

        if version_byte != 6 << 3:  # ed25519PublicKey
            return False

        checksum = crc16.crc16xmodem(payload)

        if checksum != expected_checksum:
            return False

        return True

    def validate_extended(self) -> bool:
        return False

    @property
    def network(self) -> str:
        return ''


@attr.s(frozen=True, slots=True, cmp=False)
class CosmosValidator(ValidatorBase):
    """Validates Cosmos cryptocurrency addresses."""

    name = 'CosmosCheck'
    hrp_table = ("cosmos", "cosmospub", "cosmosvalcons", "cosmosvalconspub", "cosmosvaloper", "cosmosvaloperpub")

    def validate(self) -> bool:
        try:
            address = self.request.address
            decoded_address = bech32.bech32_decode(address)
            if not decoded_address:
                return False
                
            hrp, data = decoded_address
            if not hrp or not data:
                return False

            if hrp not in self.hrp_table:
                return False

            # For Cosmos addresses, we only need to verify the HRP and that the data exists
            # The bech32_decode function already verifies the checksum
            return True
        except Exception:
            return False

    def validate_extended(self) -> bool:
        return False

    @property
    def network(self) -> str:
        return ""

    @property
    def address_type(self) -> str:
        try:
            address = self.request.address
            decoded_address = bech32.bech32_decode(address)
            if not decoded_address:
                return ""
                
            hrp, _ = decoded_address
            if not hrp:
                return ""

            if hrp not in self.hrp_table:
                return ""

            return hrp
        except Exception:
            return ""


@attr.s(frozen=True, slots=True, cmp=False)
class BitcoinBasedCheck(ValidatorBase):
    """Validates Bitcoin-based cryptocurrency addresses."""

    name = 'BitcoinBasedCheck'

    def validate(self) -> bool:
        """Validate the address."""
        if len(self.request.address) == 111:
            return self.validate_extended()

        if 25 > len(self.request.address) > 35:
            return False

        try:
            abytes = base58check.b58decode(
                self.request.address, **self.request.extras)
        except ValueError:
            return False

        # Check network first
        network = self.network
        if network == '':
            return False

        # Calculate checksum
        checksum = sha256(sha256(abytes[:-4]).digest()).digest()[:4]
        if abytes[-4:] != checksum:
            return False

        # Verify the address can be re-encoded correctly
        try:
            reencoded = base58check.b58encode(abytes, **self.request.extras)
            return self.request.address == reencoded.decode('utf-8')
        except Exception:
            return False

    def validate_extended(self) -> bool:
        if len(self.request.address) != 111:
            return False

        if self.network == '':
            return False

        # strip leading "zeros" (the "1" digit with base58)
        base58_stripped = self.request.address.lstrip("1")
        # convert base58 to decimal
        int_rep = 0
        for base58_digit in base58_stripped:
            int_rep *= 58
            try:
                int_rep += self.base58_digit_to_dec[base58_digit]
            except KeyError:
                # not a valid base58 digit -> invalid address
                return False

        # encode it to base64
        hex_rep = "{:X}".format(int_rep)
        # if the length is odd, add leading zero (needed for b16decode)
        if len(hex_rep) % 2 == 1:
            hex_rep = "0" + hex_rep
        # decode it into a binary string, padded with zeros
        # 72 bytes (extended key size) + 4 bytes (prefix version bytes)
        all_bytes = base64.b16decode(hex_rep).rjust(82, b"\0")

        # count leading zeros
        zero_count = next(zeros for zeros, byte in enumerate(all_bytes) if byte != 0)
        # compare it with the number of leading zeros lstripped at the beginning
        if len(self.request.address) - len(base58_stripped) != zero_count:
            return False

        checksum = sha256(sha256(all_bytes[:-4]).digest()).digest()[:4]
        if checksum != all_bytes[-4:]:
            return False

        return True

    @property
    def network(self) -> str:
        """Return network derived from network version bytes."""
        try:
            abytes = base58check.b58decode(
                self.request.address, **self.request.extras)
        except ValueError:
            return ''

        nbyte = abytes[0]
        for name, networks in self.request.currency.networks.items():
            if isinstance(networks, tuple):
                # Check if the first byte matches any of the network values
                if nbyte in networks:
                    return name
                # For Litecoin, also check if the address starts with 'ltc' or 'tltc'
                if name == 'main' and self.request.address.startswith('ltc'):
                    return name
                if name == 'test' and self.request.address.startswith('tltc'):
                    return name
            elif isinstance(networks, str):
                if self.request.address.startswith(networks):
                    return name
        return ''

    @property
    def address_type(self) -> str:
        """Return address type derived from network version bytes."""
        if len(self.request.address) == 0:
            return ''
        try:
            abytes = base58check.b58decode(
                self.request.address, **self.request.extras)
        except ValueError:
            return ''

        for name, networks in self.request.currency.address_types.items():
            for netw in networks:
                if netw != 0:
                    # count the prefix length in bytes
                    prefixlen = math.ceil(math.floor((math.log(netw) / math.log(2)) + 1) / 8)
                else:
                    prefixlen = 1
                address_prefix = [x for x in bytearray(abytes[:prefixlen])]
                if prefixtodec(address_prefix) == netw:
                    return name

        if len(self.request.currency.address_types.items()) == 0:
            return 'address'
        else:
            return ''


def validate(currency: str, address: str, **extras: Any) -> ValidationResult:
    """Validate a cryptocurrency address.

    Args:
        currency: The currency name or ticker to validate against
        address: The address to validate
        **extras: Any extra attributes to be passed to decoder, etc

    Returns:
        A ValidationResult object containing the validation results
    """
    request = ValidationRequest(
        currency=currency,
        address=address,
        extras=extras)
    return request.execute()


def prefixtodec(prefix):
    total = 0
    multiplier = 256
    for i in range(2, len(prefix) + 1):
        total += prefix[-i] * multiplier
        multiplier *= 256
    return total + prefix[-1]

