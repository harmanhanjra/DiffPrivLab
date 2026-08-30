"""Merkle-Patricia Trie implementation with verification harness."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional


# ── Node types ──────────────────────────────────────────────────────────────

NULL = b""
BRANCH = "BRANCH"
LEAF = "LEAF"
EXTENSION = "EXTENSION"


@dataclass
class Node:
    """Base node in the MPT."""

    node_type: str
    children: list = field(default_factory=list)
    key: bytes = b""
    value: Any = None
    hash: bytes = b""

    def is_null(self) -> bool:
        return self.node_type == "NULL"

    def is_branch(self) -> bool:
        return self.node_type == "BRANCH"

    def is_leaf(self) -> bool:
        return self.node_type == "LEAF"

    def is_extension(self) -> bool:
        return self.node_type == "EXTENSION"


def make_null() -> Node:
    return Node(node_type="NULL")


def make_branch(value: Any = None) -> Node:
    return Node(node_type="BRANCH", children=[make_null()] * 16, value=value)


def make_leaf(nibbles: bytes, value: Any) -> Node:
    return Node(node_type="LEAF", key=nibbles, value=value)


def make_extension(nibbles: bytes, child: Node) -> Node:
    return Node(node_type="EXTENSION", key=nibbles, children=[child])


# ── Nibble encoding ─────────────────────────────────────────────────────────

def bytes_to_nibbles(data: bytes) -> bytes:
    """Convert bytes to nibbles (each byte -> 2 nibbles)."""
    result = bytearray()
    for b in data:
        result.append((b >> 4) & 0x0F)
        result.append(b & 0x0F)
    return bytes(result)


def nibbles_to_bytes(nibbles: bytes) -> bytes:
    """Convert nibbles back to bytes."""
    if len(nibbles) % 2 != 0:
        raise ValueError("Nibbles length must be even")
    result = bytearray()
    for i in range(0, len(nibbles), 2):
        result.append((nibbles[i] << 4) | nibbles[i + 1])
    return bytes(result)


def common_prefix(a: bytes, b: bytes) -> int:
    """Length of common prefix between two nibble sequences."""
    i = 0
    while i < len(a) and i < len(b) and a[i] == b[i]:
        i += 1
    return i


# ── Hashing ─────────────────────────────────────────────────────────────────

def hash_node(node: Node) -> bytes:
    """Compute the hash of a node (simplified Keccak-256 style)."""
    if node.is_null():
        return hashlib.sha256(b"").digest()

    content = node.node_type.encode() + b":"
    if node.is_leaf() or node.is_extension():
        content += bytes(node.key) + b":"
        if node.is_leaf():
            content += str(node.value).encode()
        else:
            content += hash_node(node.children[0])
    elif node.is_branch():
        for child in node.children:
            content += hash_node(child)
        if node.value is not None:
            content += str(node.value).encode()

    return hashlib.sha256(content).digest()


# ── MPT Operations ──────────────────────────────────────────────────────────

class MerklePatriciaTrie:
    """Merkle-Patricia Trie with proof generation."""

    def __init__(self):
        self.root: Node = make_null()
        self._proofs: list[dict] = []

    def get(self, key: bytes) -> Optional[Any]:
        """Get value by key."""
        nibbles = bytes_to_nibbles(key)
        return self._get(self.root, nibbles)

    def _get(self, node: Node, nibbles: bytes) -> Optional[Any]:
        if node.is_null():
            return None
        if node.is_leaf():
            if node.key == nibbles:
                return node.value
            return None
        if node.is_extension():
            cp = common_prefix(node.key, nibbles)
            if cp == len(node.key):
                return self._get(node.children[0], nibbles[cp:])
            return None
        if node.is_branch():
            if not nibbles:
                return node.value
            idx = nibbles[0]
            return self._get(node.children[idx], nibbles[1:])
        return None

    def put(self, key: bytes, value: Any) -> None:
        """Insert or update a key-value pair."""
        nibbles = bytes_to_nibbles(key)
        self.root = self._put(self.root, nibbles, value)

    def _put(self, node: Node, nibbles: bytes, value: Any) -> Node:
        if node.is_null():
            return make_leaf(nibbles, value)

        if node.is_leaf():
            cp = common_prefix(node.key, nibbles)
            if cp == len(node.key) and cp == len(nibbles):
                # Exact match - update value
                return make_leaf(nibbles, value)
            if cp == len(node.key):
                # Leaf is prefix of new key
                remaining = nibbles[cp:]
                branch = make_branch()
                branch.children[remaining[0]] = self._put(
                    make_null(), remaining[1:], value
                )
                return make_extension(node.key, branch)
            if cp == len(nibbles):
                # New key is prefix of leaf
                remaining = node.key[cp:]
                branch = make_branch(value)
                branch.children[remaining[0]] = make_leaf(remaining[1:], node.value)
                return make_extension(nibbles, branch)
            # Divergence - create branch
            branch = make_branch()
            if cp > 0:
                ext_key = node.key[:cp]
                remaining_old = node.key[cp:]
                remaining_new = nibbles[cp:]
                branch.children[remaining_old[0]] = make_leaf(
                    remaining_old[1:], node.value
                )
                branch.children[remaining_new[0]] = self._put(
                    make_null(), remaining_new[1:], value
                )
                return make_extension(ext_key, branch)
            remaining_old = node.key[cp:]
            remaining_new = nibbles[cp:]
            branch.children[remaining_old[0]] = make_leaf(
                remaining_old[1:], node.value
            )
            branch.children[remaining_new[0]] = self._put(
                make_null(), remaining_new[1:], value
            )
            return branch

        if node.is_extension():
            cp = common_prefix(node.key, nibbles)
            if cp == len(node.key):
                # Extension is prefix - descend
                new_child = self._put(node.children[0], nibbles[cp:], value)
                return make_extension(node.key, new_child)
            # Divergence
            branch = make_branch()
            if cp > 0:
                ext_key = node.key[:cp]
                remaining_ext = node.key[cp:]
                remaining_new = nibbles[cp:]
                branch.children[remaining_ext[0]] = make_extension(
                    remaining_ext[1:], node.children[0]
                )
                branch.children[remaining_new[0]] = self._put(
                    make_null(), remaining_new[1:], value
                )
                return make_extension(ext_key, branch)
            remaining_ext = node.key[cp:]
            remaining_new = nibbles[cp:]
            branch.children[remaining_ext[0]] = make_extension(
                remaining_ext[1:], node.children[0]
            )
            branch.children[remaining_new[0]] = self._put(
                make_null(), remaining_new[1:], value
            )
            return branch

        if node.is_branch():
            if not nibbles:
                node.value = value
                return node
            idx = nibbles[0]
            node.children[idx] = self._put(node.children[idx], nibbles[1:], value)
            return node

        return node

    def delete(self, key: bytes) -> bool:
        """Delete a key. Returns True if key existed."""
        nibbles = bytes_to_nibbles(key)
        new_root, deleted = self._delete(self.root, nibbles)
        if deleted:
            self.root = new_root
        return deleted

    def _delete(self, node: Node, nibbles: bytes) -> tuple[Node, bool]:
        if node.is_null():
            return make_null(), False

        if node.is_leaf():
            if node.key == nibbles:
                return make_null(), True
            return node, False

        if node.is_extension():
            cp = common_prefix(node.key, nibbles)
            if cp == len(node.key):
                new_child, deleted = self._delete(node.children[0], nibbles[cp:])
                if deleted:
                    return self._collapse_extension(node.key, new_child), True
            return node, False

        if node.is_branch():
            if not nibbles:
                if node.value is not None:
                    node.value = None
                    return self._collapse_branch(node), True
                return node, False
            idx = nibbles[0]
            new_child, deleted = self._delete(node.children[idx], nibbles[1:])
            if deleted:
                node.children[idx] = new_child
                return self._collapse_branch(node), True
            return node, False

        return node, False

    def _collapse_extension(self, ext_key: bytes, child: Node) -> Node:
        """Collapse extension + child into a single node."""
        if child.is_null():
            return make_null()
        if child.is_leaf():
            return make_leaf(ext_key + child.key, child.value)
        if child.is_extension():
            return make_extension(ext_key + child.key, child.children[0])
        if child.is_branch():
            return make_extension(ext_key, child)
        return make_null()

    def _collapse_branch(self, node: Node) -> Node:
        """Collapse branch if it has only one non-null child."""
        non_null = [(i, c) for i, c in enumerate(node.children) if not c.is_null()]
        if len(non_null) == 1 and node.value is None:
            idx, child = non_null[0]
            if child.is_leaf():
                return make_leaf(bytes([idx]) + child.key, child.value)
            if child.is_extension():
                return make_extension(bytes([idx]) + child.key, child.children[0])
            if child.is_branch():
                return make_extension(bytes([idx]), child)
        return node

    def root_hash(self) -> bytes:
        """Compute the root hash of the trie."""
        return hash_node(self.root)

    # ── Proof generation ─────────────────────────────────────────────────

    def generate_proof(self, key: bytes) -> list[dict]:
        """Generate a Merkle proof for a key."""
        nibbles = bytes_to_nibbles(key)
        proof = []
        self._generate_proof(self.root, nibbles, proof)
        return proof

    def _generate_proof(
        self, node: Node, nibbles: bytes, proof: list[dict]
    ) -> Optional[Any]:
        """Recursively generate proof. Returns value if found."""
        if node.is_null():
            return None

        proof.append(
            {
                "type": node.node_type,
                "key": list(node.key),
                "hash": hash_node(node).hex(),
            }
        )

        if node.is_leaf():
            if node.key == nibbles:
                proof[-1]["value"] = node.value
                return node.value
            return None

        if node.is_extension():
            cp = common_prefix(node.key, nibbles)
            if cp == len(node.key):
                proof[-1]["child_hash"] = hash_node(node.children[0]).hex()
                return self._generate_proof(node.children[0], nibbles[cp:], proof)
            return None

        if node.is_branch():
            if not nibbles:
                if node.value is not None:
                    proof[-1]["value"] = node.value
                return node.value
            idx = nibbles[0]
            proof[-1]["child_index"] = idx
            proof[-1]["child_hash"] = hash_node(node.children[idx]).hex()
            return self._generate_proof(node.children[idx], nibbles[1:], proof)

        return None

    def verify_proof(
        self, root_hash: bytes, key: bytes, proof: list[dict]
    ) -> Optional[Any]:
        """Verify a Merkle proof against a root hash."""
        if not proof:
            return None

        nibbles = bytes_to_nibbles(key)
        current_nibbles = nibbles
        value = None

        for i, step in enumerate(proof):
            node_type = step["type"]
            node_key = bytes(step["key"])
            expected_hash = bytes.fromhex(step["hash"])

            if i == 0:
                # First node must match root hash
                if expected_hash != root_hash:
                    return None

            if node_type == "LEAF":
                if node_key == current_nibbles:
                    value = step.get("value")
                else:
                    return None
            elif node_type == "EXTENSION":
                cp = common_prefix(node_key, current_nibbles)
                if cp != len(node_key):
                    return None
                current_nibbles = current_nibbles[cp:]
            elif node_type == "BRANCH":
                if not current_nibbles:
                    value = step.get("value")
                else:
                    idx = current_nibbles[0]
                    current_nibbles = current_nibbles[1:]

        return value

    def generate_exclusion_proof(self, key: bytes) -> list[dict]:
        """Generate a proof that a key is NOT in the trie."""
        nibbles = bytes_to_nibbles(key)
        proof = []
        found = self._generate_proof(self.root, nibbles, proof)
        if found is not None:
            return []  # Key exists, no exclusion proof
        return proof

    def verify_exclusion_proof(
        self, root_hash: bytes, key: bytes, proof: list[dict]
    ) -> bool:
        """Verify that a key is NOT in the trie."""
        if not proof:
            return False

        # Verify the proof path is valid but doesn't lead to the key
        nibbles = bytes_to_nibbles(key)
        current_nibbles = nibbles

        for i, step in enumerate(proof):
            node_type = step["type"]
            node_key = bytes(step["key"])
            expected_hash = bytes.fromhex(step["hash"])

            if i == 0:
                if expected_hash != root_hash:
                    return False

            if node_type == "LEAF":
                # Key mismatch proves exclusion
                return node_key != current_nibbles
            elif node_type == "EXTENSION":
                cp = common_prefix(node_key, current_nibbles)
                if cp != len(node_key):
                    return True  # Path diverges - exclusion proven
                current_nibbles = current_nibbles[cp:]
            elif node_type == "BRANCH":
                if not current_nibbles:
                    return step.get("value") is None
                idx = current_nibbles[0]
                current_nibbles = current_nibbles[1:]

        return True

    # ── Serialization ─────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialize trie to dictionary."""
        return self._node_to_dict(self.root)

    def _node_to_dict(self, node: Node) -> dict:
        if node.is_null():
            return {"type": "NULL"}
        result = {"type": node.node_type}
        if node.is_leaf():
            result["key"] = list(node.key)
            result["value"] = node.value
        elif node.is_extension():
            result["key"] = list(node.key)
            result["child"] = self._node_to_dict(node.children[0])
        elif node.is_branch():
            result["children"] = [
                self._node_to_dict(c) for c in node.children
            ]
            if node.value is not None:
                result["value"] = node.value
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "MerklePatriciaTrie":
        """Deserialize trie from dictionary."""
        trie = cls()
        trie.root = cls._node_from_dict(data)
        return trie

    @classmethod
    def _node_from_dict(cls, data: dict) -> Node:
        node_type = data["type"]
        if node_type == "NULL":
            return make_null()
        if node_type == "LEAF":
            return make_leaf(bytes(data["key"]), data["value"])
        if node_type == "EXTENSION":
            child = cls._node_from_dict(data["child"])
            return make_extension(bytes(data["key"]), child)
        if node_type == "BRANCH":
            children = [cls._node_from_dict(c) for c in data["children"]]
            value = data.get("value")
            return Node(node_type="BRANCH", children=children, value=value)
        return make_null()