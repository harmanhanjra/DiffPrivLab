"""MPT Lab — Verified Merkle-Patricia Trie.

A from-scratch implementation of the Merkle-Patricia Trie with:
- Full MPT: NULL, BRANCH, LEAF, and EXTENSION nodes
- Core operations: get, put, delete with rebalancing
- Merkle proofs: Inclusion and exclusion proof generation
- Proof verification: Independent verifier against a root hash
- Verification harness: Property + mutation testing as a CI exit-code gate

Usage:
    python -m mptlab verify [--seed SEED] [--trials N]
    python -m mptlab demo
"""

from mptlab import MerklePatriciaTrie

if __name__ == "__main__":
    import sys
    from mptlab.cli import main

    sys.exit(main())