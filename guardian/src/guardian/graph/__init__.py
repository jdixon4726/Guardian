"""
Guardian Decision Graph

Models machine operational behavior as a directed graph of actors,
actions, targets, systems, and decisions. Enables cascade detection,
blast radius computation, and graph-aware drift analysis.

Two-layer architecture:
  Layer 1 (Event Graph)   — raw, time-bound decision events and their relationships
  Layer 2 (Intelligence)  — derived aggregates: blast radius, cascades, drift patterns
"""
