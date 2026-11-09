"""Evidence packets and a replay engine for autorate.

The portal tier never computes a statistic (PRD I1). M1 shipped the packet
contract and the CLI that builds, verifies, renders and replays packets
produced by the pinned ``autorate`` distribution. M2 adds the run engine: one
executor, run rows that carry argv and exit code, a pinned-distribution
registry that can contradict a forged packet, and ``doctor``.
"""

__version__ = "0.1.0"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_RUN = 3
EXIT_REFUSED = 4
