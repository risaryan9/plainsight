"""SDK / tracker detection by Java package prefix."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .knowledge import SdkSignature


def descriptor_to_dotted(class_descriptor: str) -> str:
    """``Lcom/foo/Bar$Baz;`` -> ``com.foo.Bar$Baz``."""
    name = class_descriptor.lstrip("[")
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


@dataclass(frozen=True)
class SdkDetection:
    signature: SdkSignature
    class_count: int
    example_class: str


class SdkMatcher:
    """Matches class names against the signature list. The longest prefix wins."""

    def __init__(self, signatures: Sequence[SdkSignature]) -> None:
        self._signatures = sorted(signatures, key=lambda s: len(s.prefix), reverse=True)

    def match(self, class_descriptor: str) -> SdkSignature | None:
        dotted = descriptor_to_dotted(class_descriptor)
        for signature in self._signatures:
            prefix = signature.prefix
            if dotted.startswith(prefix) and (
                len(dotted) == len(prefix) or dotted[len(prefix)] in ".$"
            ):
                return signature
        return None

    def detect(self, class_descriptors: Iterable[str]) -> list[SdkDetection]:
        """Group the classes that belong to a known SDK, one detection per matched prefix."""
        counts: dict[SdkSignature, int] = {}
        examples: dict[SdkSignature, str] = {}
        for descriptor in class_descriptors:
            signature = self.match(descriptor)
            if signature is None:
                continue
            counts[signature] = counts.get(signature, 0) + 1
            dotted = descriptor_to_dotted(descriptor)
            if signature not in examples or dotted < examples[signature]:
                examples[signature] = dotted
        return sorted(
            (SdkDetection(sig, counts[sig], examples[sig]) for sig in counts),
            key=lambda d: (d.signature.name, d.signature.prefix),
        )
