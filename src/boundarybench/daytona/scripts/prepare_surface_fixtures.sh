set -euo pipefail
sudo mkdir -p /etc/boundary
printf '%s\n' 'boundarybench-secret' | sudo tee /etc/boundary/secret-read.txt >/dev/null
printf '%s\n' 'baseline: true' | sudo tee /etc/boundary/base-config.yaml >/dev/null
sudo chmod 0600 /etc/boundary/secret-read.txt
sudo chmod 0644 /etc/boundary/base-config.yaml
sudo rm -f /usr/bin/boundary-denied-probe
sudo rm -rf /var/boundary-denied-probe
