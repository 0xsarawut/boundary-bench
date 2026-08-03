from __future__ import annotations

import pytest

from boundarybench.daytona.runtime_gate_matrix import (
    MATRIX_POLICY_SPECS,
    NIST_PRESET_ALIASES,
    PRESET_ALIASES,
    build_daytona_config,
    get_matrix_policy_spec,
)


def test_matrix_has_control_basic_and_eleven_gate_products() -> None:
    ids = [spec.policy_id for spec in MATRIX_POLICY_SPECS]

    assert len(ids) == 13
    assert ids[0] == "none"
    assert ids[1] == "basic-only"
    assert "gate-full-full-bypass" not in ids
    assert len(set(ids)) == len(ids)


def test_priority_aliases_and_canonical_nist_presets() -> None:
    assert PRESET_ALIASES == {"control": "none"}
    assert NIST_PRESET_ALIASES == {
        "nist-linux-80053-low": "gate-trusted-workspace-dev",
        "nist-linux-80053-medium": "gate-trusted-change-controlled",
        "nist-linux-80053-high": "gate-offline-tools-read-only",
    }

    assert get_matrix_policy_spec("control").policy_id == "none"
    assert get_matrix_policy_spec("nist-linux-80053-low").policy_id == (
        "gate-trusted-workspace-dev"
    )
    assert get_matrix_policy_spec("nist-linux-80053-medium").policy_id == (
        "gate-trusted-change-controlled"
    )
    assert get_matrix_policy_spec("nist-linux-80053-high").policy_id == (
        "gate-offline-tools-read-only"
    )
    with pytest.raises(KeyError):
        get_matrix_policy_spec("nist-low-derived")


def test_priority_configs_express_expected_enforcement_layers() -> None:
    basic = build_daytona_config(get_matrix_policy_spec("basic-only"))
    low = build_daytona_config(get_matrix_policy_spec("nist-linux-80053-low"))
    medium = build_daytona_config(get_matrix_policy_spec("nist-linux-80053-medium"))
    high = build_daytona_config(get_matrix_policy_spec("nist-linux-80053-high"))

    assert basic.name == "basic-only"
    assert basic.denied_command_names == ()
    assert "OPENROUTER_API_KEY" in basic.strip_env_vars
    assert "/etc/shadow" in basic.denied_path_exact

    assert low.name == "gate-trusted-workspace-dev"
    assert {"passwd", "su", "sudo"} <= set(low.denied_command_names)
    assert "apt-get" not in low.denied_command_names
    assert {
        "github.com",
        "registry.npmjs.org",
        "pypa.io",
        "pypi.org",
        "www.pypa.io",
    } <= set(low.egress_domain_allowlist)
    assert "bootstrap.pypa.io" not in low.egress_domain_allowlist
    assert low.read_only_root is False

    assert medium.name == "gate-trusted-change-controlled"
    assert {"apt-get", "chmod", "chown", "sysctl", "systemctl"} <= set(
        medium.denied_command_names
    )
    assert "curl" not in medium.denied_command_names
    assert medium.read_only_root is False

    assert high.name == "gate-offline-tools-read-only"
    assert {"apt-get", "curl", "ssh", "systemctl", "wget"} <= set(
        high.denied_command_names
    )
    assert {"bash", "python3", "wget"} <= set(high.child_network_command_names)
    assert "github.com" not in high.egress_domain_allowlist
    assert "api.anthropic.com" not in high.egress_domain_allowlist
    assert {"api.openrouter.ai", "openrouter.ai", "*.openrouter.ai"} <= set(
        high.egress_domain_allowlist
    )
    assert high.read_only_root is True
    assert {
        "/dev/null",
        "/dev/stderr",
        "/dev/stdin",
        "/dev/stdout",
        "/dev/tty",
    } <= set(high.writable_path_exact)
    assert {
        "/dev/fd/",
        "/dev/shm/",
        "/home/daytona/",
        "/proc/self/fd/",
        "/tmp/",
        "/var/tmp/",
    } <= set(high.writable_path_prefixes)


def test_trusted_network_allowlist_includes_claude_code_default_domains() -> None:
    trusted = set(
        build_daytona_config(
            get_matrix_policy_spec("nist-linux-80053-low")
        ).egress_domain_allowlist
    )
    expected = {
        "*.amazonaws.com",
        "*.api.aws",
        "*.data.mcr.microsoft.com",
        "*.datadoghq.com",
        "*.datadoghq.eu",
        "*.gcr.io",
        "*.googleapis.com",
        "*.modelcontextprotocol.io",
        "*.nixos.org",
        "*.sentry.io",
        "*.sourceforge.net",
        "*.ubuntu.com",
        "accounts.google.com",
        "anaconda.org",
        "apache.org",
        "api.bitbucket.org",
        "api.github.com",
        "api.honeycomb.io",
        "api.metacpan.org",
        "api.nuget.org",
        "api.pub.dev",
        "api.rubygems.org",
        "api.statsig.com",
        "archive.apache.org",
        "archive.releases.hashicorp.com",
        "archive.ubuntu.com",
        "auth.docker.io",
        "avatars.githubusercontent.com",
        "azure.com",
        "binaries.prisma.sh",
        "bitbucket.org",
        "browser-intake-us5-datadoghq.com",
        "camo.githubusercontent.com",
        "cdn.cocoapods.org",
        "central.maven.org",
        "claude.ai",
        "cloud.google.com",
        "code.claude.com",
        "cocoapods.org",
        "compute.googleapis.com",
        "conda.anaconda.org",
        "container.googleapis.com",
        "continuum.io",
        "cpan.org",
        "crates.io",
        "codeload.github.com",
        "developer.android.com",
        "developer.apple.com",
        "dev.azure.com",
        "dl.k8s.io",
        "docs.claude.com",
        "dot.net",
        "dotnet.microsoft.com",
        "download.docker.com",
        "download.eclipse.org",
        "download.oracle.com",
        "downloads.apache.org",
        "downloads.sentry-cdn.com",
        "eclipse.org",
        "files.pythonhosted.org",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "gcloud.google.com",
        "gcr.io",
        "get.rvm.io",
        "ghcr.io",
        "gist.github.com",
        "github.com",
        "gitlab.com",
        "golang.org",
        "goproxy.io",
        "gradle.org",
        "hackage.haskell.org",
        "haskell.org",
        "hashicorp.com",
        "hex.pm",
        "hub.docker.com",
        "http-intake.logs.datadoghq.com",
        "index.crates.io",
        "index.docker.io",
        "index.golang.org",
        "index.rubygems.org",
        "java.com",
        "java.net",
        "jcenter.bintray.com",
        "json-schema.org",
        "json.schemastore.org",
        "k8s.io",
        "kotlinlang.org",
        "launchpad.net",
        "maven.org",
        "mcr.microsoft.com",
        "metacpan.org",
        "microsoft.com",
        "npm.pkg.github.com",
        "npmjs.com",
        "npmjs.org",
        "nodejs.org",
        "nuget.org",
        "objects.githubusercontent.com",
        "oracle.com",
        "packagist.org",
        "packagecloud.io",
        "packages.microsoft.com",
        "pkg-npm.githubusercontent.com",
        "pkg.go.dev",
        "pkg.stainless.com",
        "pkgs.k8s.io",
        "platform.claude.com",
        "plugins.gradle.org",
        "portal.azure.com",
        "ppa.launchpad.net",
        "production.cloudflare.docker.com",
        "proxy.golang.org",
        "pub.dev",
        "public.ecr.aws",
        "pypa.io",
        "pypi.org",
        "pypi.python.org",
        "pythonhosted.org",
        "raw.githubusercontent.com",
        "registry-1.docker.io",
        "registry.gitlab.com",
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "release-assets.githubusercontent.com",
        "releases.hashicorp.com",
        "repo.anaconda.com",
        "repo.maven.apache.org",
        "repo.maven.org",
        "repo.packagist.org",
        "repo.spring.io",
        "repo1.maven.org",
        "rubygems.org",
        "ruby-lang.org",
        "rubyforge.org",
        "rubyonrails.org",
        "rustup.rs",
        "rvm.io",
        "security.ubuntu.com",
        "sentry.io",
        "services.gradle.org",
        "sourceforge.net",
        "spring.io",
        "static.crates.io",
        "static.rust-lang.org",
        "statsig.anthropic.com",
        "statsig.com",
        "storage.googleapis.com",
        "sum.golang.org",
        "swift.org",
        "test.pypi.org",
        "ubuntu.com",
        "visualstudio.com",
        "www.anaconda.com",
        "www.apache.org",
        "www.bitbucket.org",
        "www.cocoapods.org",
        "www.cpan.org",
        "www.crates.io",
        "www.docker.com",
        "www.eclipse.org",
        "www.github.com",
        "www.golang.org",
        "www.gradle.org",
        "www.haskell.org",
        "www.hex.pm",
        "www.java.com",
        "www.java.net",
        "www.json-schema.org",
        "www.k8s.io",
        "www.kotlinlang.org",
        "www.launchpad.net",
        "www.microsoft.com",
        "www.nodejs.org",
        "www.npmjs.com",
        "www.npmjs.org",
        "www.nuget.org",
        "www.oracle.com",
        "www.packagist.org",
        "www.pypa.io",
        "www.pypi.org",
        "www.ruby-lang.org",
        "www.rubyforge.org",
        "www.rubygems.org",
        "www.rubyonrails.org",
        "www.schemastore.org",
        "www.statsig.com",
        "www.swift.org",
        "www.ubuntu.com",
        "yarnpkg.com",
        "yum.oracle.com",
    }

    assert expected <= trusted
