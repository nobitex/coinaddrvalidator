# pylint: disable=inherit-non-class,no-self-argument,no-method-argument
# pylint: disable=unexpected-special-method-signature,arguments-differ

"""
:mod:`coinaddr.interfaces`
~~~~~~~~~~~~~~~~~~~~~~~~

Various interfaces for the coinaddr package.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, Optional


class INamedInstanceContainer(ABC):
    """Contains all currencies instantiated."""

    @property
    @abstractmethod
    def instances(self) -> Dict[str, Any]:
        """Mapping of instance.name -> instance"""
        pass

    @abstractmethod
    def __getitem__(self, name: str) -> Any:
        """Return the named instance"""
        pass

    @abstractmethod
    def __setitem__(self, name: str, obj: Any) -> None:
        """Add the named instance to the mapping of instances"""
        pass

    @abstractmethod
    def __delitem__(self, name: str) -> None:
        """Remove the named instance from the mapping of instances"""
        pass

    @abstractmethod
    def __contains__(self, name: str) -> bool:
        """Return true if we contain the named instance"""
        pass

    @abstractmethod
    def __iter__(self) -> Iterator[Any]:
        """Return an iterable, iterating all instances"""
        pass

    @abstractmethod
    def get(self, name: str, default: Any = None) -> Any:
        """Return the named instance if we contain it, else default"""
        pass


class INamedSubclassContainer(ABC):
    """Contains a weakvaluedict of subclasses."""

    @property
    @abstractmethod
    def subclasses(self) -> Dict[str, Any]:
        """Mapping of subclass.name -> subclass"""
        pass

    @abstractmethod
    def __getitem__(self, name: str) -> Any:
        """Return the named subclass"""
        pass

    @abstractmethod
    def __setitem__(self, name: str, obj: Any) -> None:
        """Add the named subclass to the mapping of subclasses"""
        pass

    @abstractmethod
    def __delitem__(self, name: str) -> None:
        """Remove the named subclass from the mapping of subclasses"""
        pass

    @abstractmethod
    def __contains__(self, name: str) -> bool:
        """Return true if we contain the named subclass"""
        pass

    @abstractmethod
    def __iter__(self) -> Iterator[Any]:
        """Return an iterable, iterating all subclasses"""
        pass

    @abstractmethod
    def get(self, name: str, default: Any = None) -> Any:
        """Return the named subclass if we contain it, else default"""
        pass


class ICurrency(ABC):
    """A cryptocurrency address specification."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of currency"""
        pass

    @property
    @abstractmethod
    def ticker(self) -> str:
        """Ticker symbol for currency"""
        pass

    @property
    @abstractmethod
    def validator(self) -> str:
        """Validator name for validation"""
        pass

    @property
    @abstractmethod
    def networks(self) -> Dict[str, Any]:
        """The networks and version bytes for those networks"""
        pass

    @property
    @abstractmethod
    def charset(self) -> Optional[bytes]:
        """For base58Check based currencies, custom charset."""
        pass


class IValidator(ABC):
    """A cryptocurrency address validator."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of validator"""
        pass

    @property
    @abstractmethod
    def network(self) -> str:
        """Network name of address being validated"""
        pass

    @abstractmethod
    def validate(self) -> bool:
        """Validate the address type, True if valid, else False."""
        pass


class IValidationRequest(ABC):
    """Contains the data and helpers for a given validation request."""

    @property
    @abstractmethod
    def currency(self) -> str:
        """The currency name or ticker being validated"""
        pass

    @property
    @abstractmethod
    def address(self) -> str:
        """The address to be validated"""
        pass

    @property
    @abstractmethod
    def extras(self) -> Dict[str, Any]:
        """Any extra attributes to be passed to decoder, etc"""
        pass

    @property
    @abstractmethod
    def networks(self) -> str:
        """Concatenated list of all network versions for currency"""
        pass

    @abstractmethod
    def execute(self) -> 'IValidationResult':
        """Executes the request and returns a ValidationResult object"""
        pass


class IValidationResult(ABC):
    """Represents all data for a validation result."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of currency for address validated"""
        pass

    @property
    @abstractmethod
    def ticker(self) -> str:
        """Ticker of currency for address validated"""
        pass

    @property
    @abstractmethod
    def address(self) -> str:
        """The address that was validated"""
        pass

    @property
    @abstractmethod
    def valid(self) -> bool:
        """Boolean representing whether the address is valid"""
        pass

    @property
    @abstractmethod
    def network(self) -> Optional[str]:
        """Name of network the address belongs to if applicable"""
        pass

    @property
    @abstractmethod
    def is_extended(self) -> bool:
        """boolean representing whether the address is extended key or not"""
        pass

