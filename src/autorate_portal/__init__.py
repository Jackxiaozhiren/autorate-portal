"""M1 evidence packets for autorate.

The portal tier never computes a statistic (PRD I1). This milestone ships the
packet contract and the CLI that builds, verifies, renders and replays packets
produced by the pinned ``autorate`` distribution.
"""

__version__ = "0.1.0"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_RUN = 3
EXIT_REFUSED = 4
