from typing import Generic, Self, TypeVar, TypedDict
from abc import ABC, abstractmethod

D = TypeVar("D")


class Deserializable(ABC, Generic[D]):
    @abstractmethod
    def from_dict(self, dict: D) -> Self:
        raise NotImplementedError()


S = TypeVar("S", TypedDict, TypedDict)


class Serializable(ABC, Generic[S]):
    @abstractmethod
    def to_dict(self) -> S:
        raise NotImplementedError()

    def __eq__(self, value: object, /) -> bool:
        if not isinstance(value, self.__class__):
            return False
        return self.to_dict() == value.to_dict()

    def __hash__(self) -> int:
        return hash(frozenset(self.to_dict().items()))
