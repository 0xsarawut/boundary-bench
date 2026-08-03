"""Pinned Harbor Terminus-2 runtime bundle (see UPSTREAM.md).

Ownership boundary:

- Ours: the thin ``boundarybench.harness.terminus_2`` adapter, the
  sandbox/secret boundary, artifact + trace translation (``trace.py``), and
  post-agent cleanup.
- Upstream Harbor: the agent loop, prompt/parser, tmux implementation, and
  dependency graph. We import Harbor's official ``Terminus2``; nothing here
  reimplements the agent.

``bridge.py`` and ``patches.py`` are sandbox-side sources shipped as package
resources — they run inside the hardened Daytona sandbox against the pinned
Harbor install, never in the controller process.
"""
