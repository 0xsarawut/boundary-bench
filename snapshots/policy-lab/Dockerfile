# boundary-policy-lab-v1 — go-forward Daytona snapshot for the native-enforcement
# policy benchmark. Replaces the hand-built, agentsh-named `agentsh-harness-lab-v11`
# (which had no in-repo recipe). Agentsh is retired; this image bakes ONLY the native
# toolchain the hardening path needs, so provisioning stops paying per-sandbox apt cost
# and stops being tribal/unversioned.
#
# Base: Debian 13 (trixie) — matches the validated `daytona-small` runtime (kernel 6.8,
# util-linux 2.41 → setpriv >= 2.28 OK). The Phase-0 spikes proved nftables + read-only
# bind mounts + setpriv cap-drop all work as root on this runtime.
#
# Exec model: execs as ROOT by default (no USER directive), matching the controller-root
# model the hardening wrapper assumes (`sudo unshare --mount -- setpriv --reuid daytona`).
# The `daytona` user exists for the setpriv drop but is deliberately NOT a sudoer — that
# absence IS the P1 "not in the sudoers file" native posture; nothing to remove at runtime.
#
# NOTE (validate before pushing to prod): confirm Daytona runs a custom snapshot exec-as-root
# (not forced to a default user) and grants full caps (CAP_NET_ADMIN + CAP_SYS_ADMIN) the
# same way daytona-small does. If Daytona exposes the daytona-small base as a registry ref,
# `FROM` that instead to match the spiked runtime exactly.
FROM debian:13-slim

# Native-enforcement + hardening toolchain (superset of terminalbench/scripts/sandbox_base.sh,
# minus agentsh, plus nftables):
#   nftables iproute2      -> N-axis firewall (NEW; the redesign's egress backstop)
#   util-linux             -> setpriv / unshare / mount (F/P axes)
#   sudo passwd            -> native privilege errors ("not in the sudoers file")
#   gcc libseccomp-dev linux-libc-dev -> in-VM compile of the RETAINED-unwired legacy
#                             seccomp/landlock/LD_PRELOAD path (kept for the old-vs-new A/B)
#   python3* git curl ca-certificates bash -> harness runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
      nftables iproute2 util-linux sudo passwd \
      gcc libseccomp-dev linux-libc-dev \
      python3 python3-venv python3-dev \
      git ca-certificates curl bash \
 && rm -rf /var/lib/apt/lists/*

# `daytona` user for the setpriv drop (NOT added to sudoers) + a real-bash copy at
# /bin/bash.real (independent of agentsh — sandbox_base.sh:47 does this at runtime too).
RUN useradd -m -s /bin/bash daytona \
 && cp /bin/bash /bin/bash.real
