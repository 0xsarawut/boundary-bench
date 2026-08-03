set -euo pipefail

echo "ensure-agentsh-binary: checking"

download_dir="/tmp/boundarybench-agentsh-install"
cleanup_agentsh_downloads() {
  rm -rf "$download_dir"
}
trap cleanup_agentsh_downloads EXIT

if [ -x /usr/bin/agentsh ]; then
  /usr/bin/agentsh --version >/dev/null 2>&1 || true
  echo "AGENTSH_BINARY_OK"
  exit 0
fi

agentsh_path="$(command -v agentsh || true)"
if [ -n "$agentsh_path" ]; then
  mkdir -p /usr/bin
  ln -sf "$agentsh_path" /usr/bin/agentsh
  /usr/bin/agentsh --version >/dev/null 2>&1 || true
  echo "AGENTSH_BINARY_OK"
  exit 0
fi

AGENTSH_VERSION=__AGENTSH_VERSION__
case "$(uname -m)" in
  x86_64|amd64)
    release_arch="amd64"
    deb_sha="3967b3e5713c368f6b342ed4caee20a10cb604c53af24b9850dcecce49db98b0"
    rpm_sha="d727906258ac2f70e7e1e656d880163c365edd442ddc6b0c07b867bc6ff5b3f6"
    tar_sha="40475f831adf57488e8987bbdc15a170a739dd98795d89de8c4b0d204ad1b2fc"
    ;;
  aarch64|arm64)
    release_arch="arm64"
    deb_sha="cf2b499adfb32de4ea6dc9b3b3df89b1cec906dea82570f3c79d5ab31fb17b53"
    rpm_sha="02f6cf6c1b898428e5f91502586cd164ba8c03f91048c951b78ed8db822856d8"
    tar_sha="d503b89d7b51d1de3c995715e4f1f502658c1c3e2385712f04d29ed51ae33464"
    ;;
  *)
    echo "ensure-agentsh-binary: unsupported architecture $(uname -m)"
    exit 1
    ;;
esac

mkdir -p "$download_dir"

download_asset() {
  asset_name="$1"
  output_path="$2"
  url="https://github.com/canyonroad/agentsh/releases/download/v${AGENTSH_VERSION}/${asset_name}"
  curl -fsSL --retry 3 --retry-delay 2 -o "$output_path" "$url"
}

verify_sha256() {
  expected="$1"
  file_path="$2"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected" "$file_path" | sha256sum -c -
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected" "$file_path" | shasum -a 256 -c -
  else
    echo "ensure-agentsh-binary: no sha256 checker available"
    exit 1
  fi
}

install_from_tarball() {
  asset_name="agentsh_${AGENTSH_VERSION}_linux_${release_arch}.tar.gz"
  archive_path="$download_dir/$asset_name"
  extract_dir="$download_dir/tarball"
  rm -rf "$extract_dir"
  mkdir -p "$extract_dir"
  download_asset "$asset_name" "$archive_path"
  verify_sha256 "$tar_sha" "$archive_path"
  tar -xzf "$archive_path" -C "$extract_dir"
  install -m 0755 "$extract_dir/agentsh" /usr/bin/agentsh
  install -m 0755 "$extract_dir/agentsh-shell-shim" /usr/bin/agentsh-shell-shim
  install -m 0755 "$extract_dir/agentsh-unixwrap" /usr/bin/agentsh-unixwrap
  install -m 0755 "$extract_dir/agentsh-stub" /usr/bin/agentsh-stub
  install -m 0755 "$extract_dir/libagentsh-ptracer.so" /usr/lib/libagentsh-ptracer.so
  install -m 0755 "$extract_dir/libenvshim.so" /usr/lib/libenvshim.so
  if command -v ldconfig >/dev/null 2>&1; then
    ldconfig || true
  fi
}

if command -v dpkg >/dev/null 2>&1; then
  asset_name="agentsh_${AGENTSH_VERSION}_linux_${release_arch}.deb"
  package_path="$download_dir/$asset_name"
  download_asset "$asset_name" "$package_path"
  verify_sha256 "$deb_sha" "$package_path"
  if ! dpkg -i "$package_path"; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -qq || true
      apt-get install -y -f -qq >/dev/null
      dpkg -i "$package_path"
    else
      exit 1
    fi
  fi
elif command -v rpm >/dev/null 2>&1; then
  asset_name="agentsh_${AGENTSH_VERSION}_linux_${release_arch}.rpm"
  package_path="$download_dir/$asset_name"
  download_asset "$asset_name" "$package_path"
  verify_sha256 "$rpm_sha" "$package_path"
  rpm -Uvh --replacepkgs "$package_path"
else
  install_from_tarball
fi

test -x /usr/bin/agentsh
/usr/bin/agentsh --version >/dev/null 2>&1 || true
echo "AGENTSH_BINARY_OK"
