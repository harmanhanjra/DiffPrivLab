# Why This Differential Privacy Engine?

"Differential privacy" tutorials show the Laplace mechanism formula and stop. None prove:
- That the budget accountant actually enforces the total ε limit
- That composition theorems are correctly implemented
- That sensitivity computation matches theoretical bounds
- That a broken implementation would fail the harness

This project fills the gap with a zero-dependency DP library and a 7-gate verification harness.

## The Problem Space

Differential privacy is now standard in government (US Census), tech (Apple, Google), and academia. But:
1. Most educational code is illustrative, not verified
2. Composition theorems are stated but rarely implemented correctly
3. Budget accounting bugs are silent — they don't crash, they just leak more than claimed

## Why Verify?

A DP implementation might "work" for simple cases but fail catastrophically under composition. Consider:
- 10 queries each with ε=0.1 → total ε=1.0 (basic composition)
- But advanced composition gives √(2·10·ln(1/δ'))·0.1 + ... which is tighter
- Getting this wrong means either over-protecting (useless noise) or under-protecting (privacy leak)

## The Series Context

This is Cycle 32 of an autonomous R&D series. The series has filled:
- CodeSec (AI security review), HookDoctor (webhook diagnostics), Onboarder (checklist generator)
- TensorForge (autograd engine), RingProxy (consistent-hash LB), ConvergeKit (CRDTs)
- RaftLab (Raft consensus), PhoenixKV (WAL durability), RegexLab (Thompson-NFA)
- RegAllocLab (register allocation), SeedKit (BitTorrent), DnsCacheGuard (DNS poisoning)
- RankLab (BM25 search), Mergelab (3-way merge), QosLab (MQTT QoS)
- PhysLab (physics engine), GClab (garbage collection), Annlab (HNSW ANN index)
- Compresslab (LZ77+Huffman), Bftlab (BFT consensus), Mempoolab (mempool/MEV)
- Forklab (fork choice), Bloomlab (Bloom filter), Satlab (DPLL SAT solver)
- McpGuardLab (MCP security), TypeSoundLab (type inference), Malloclab (memory allocator)

DiffPrivLab opens the **Differential Privacy** pillar — first time a "build your own DP" ships with correctness proofs for budget accounting, composition theorems, and sensitivity analysis.
