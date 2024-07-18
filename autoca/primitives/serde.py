from typing import Any, Dict, Self
from abc import ABC, abstractmethod

class Deserializable(ABC):
    @abstractmethod
    def from_dict(self, dict: Dict[str, Any]) -> Self:
        raise NotImplementedError()

class Serializable(ABC):
    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError()

    def __eq__(self, value: object, /) -> bool:
        if not isinstance(value, self.__class__):
            return False
        return self.to_dict() == value.to_dict()
