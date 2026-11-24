from abc import ABC, abstractmethod
from core.finding import Finding


class Scanner(ABC):
    name: str

    @abstractmethod
    def run(self, target: str) -> str:
        """Run the tool and return its raw output."""

    @abstractmethod
    def parse(self, raw: str) -> list[Finding]:
        """Convert raw tool output into common findings."""