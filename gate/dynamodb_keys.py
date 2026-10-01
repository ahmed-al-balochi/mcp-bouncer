"""Sort-key encoding shared by the DynamoDB backends.

DynamoDB compares string sort keys lexically, so an epoch timestamp sort key
must be fixed width and zero padded or "1000000.0" would sort before "9999.0".
"""

from __future__ import annotations

SK_WIDTH = 16
SK_DECIMALS = 6

_FORMAT = f"0{SK_WIDTH + SK_DECIMALS + 1}.{SK_DECIMALS}f"


def numeric_sk(value: float) -> str:
    """Encode an epoch timestamp as a lexically sortable fixed-width string."""
    return format(value, _FORMAT)
