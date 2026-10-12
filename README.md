# Cloudflare IPv6 DNS updater

A small, dependency-free service that keeps existing Cloudflare `AAAA` records pointed at this server's public IPv6 address. It asks the Linux kernel which source address it would use for a public IPv6 route, checks each configured record, and only calls Cloudflare when an address differs.

## Cloudflare setup

1. In Cloudflare, create every `AAAA` record you want the service to manage. Its initial address can be the server's current IPv6 address.
2. Copy the **Zone ID** from the zone's overview page.
3. Create an API token from the **Edit zone DNS** template. Restrict its zone resources to the one zone being updated. Do not use the Global API Key.

The updater needs `DNS Write` on the selected zone. It uses Cloudflare's list-record and patch-record endpoints; patching only `content` preserves settings such as TTL and proxying.

## Install on Ubuntu 24.04

Install Go from Ubuntu's packages, clone this repository, and build it:

```sh
sudo apt update
sudo apt install -y golang-go
git clone YOUR_REPOSITORY_URL
cd cloudflare-dns-updater
go test ./...
go build -trimpath -ldflags='-s -w' -o cloudflare-dns-updater .
sudo install -o root -g root -m 0755 cloudflare-dns-updater /usr/local/bin/cloudflare-dns-updater
```

Install the service and create its locked-down user:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin cloudflare-dns-updater
sudo install -o root -g root -m 0644 cloudflare-dns-updater.service /etc/systemd/system/cloudflare-dns-updater.service
sudo install -o root -g cloudflare-dns-updater -m 0640 cloudflare-dns-updater.env.example /etc/cloudflare-dns-updater.env
sudoedit /etc/cloudflare-dns-updater.env
sudo systemctl daemon-reload
sudo systemctl enable --now cloudflare-dns-updater
```

Check the result and follow logs:

```sh
systemctl status cloudflare-dns-updater
journalctl -u cloudflare-dns-updater -f
```

Run a one-off check without starting the service:

```sh
sudo sh -c 'set -a; . /etc/cloudflare-dns-updater.env; set +a; exec runuser -u cloudflare-dns-updater -- /usr/local/bin/cloudflare-dns-updater -once'
```

## Configuration

| Variable | Required | Default | Meaning |
|---|---:|---|---|
| `CF_API_TOKEN` | yes | | Scoped Cloudflare API token |
| `CF_ZONE_ID` | yes | | Cloudflare zone ID |
| `CF_RECORDS` | yes | | Comma-separated, existing AAAA record names |
| `CHECK_INTERVAL` | no | `5m` | Check frequency as a Go duration |
| `IPV6_INTERFACE` | no | | Pin address discovery to an interface, such as `eth0` |
| `IPV6_ROUTE_PROBE` | no | `[2606:4700:4700::1111]:53` | IPv6 destination used only to ask the kernel for source-address selection |
| `CF_API_URL` | no | Cloudflare API v4 | Override intended for tests |

The route probe opens an unconnected-to-application UDP socket; it sends no DNS request. If `IPV6_INTERFACE` is set, the first public IPv6 address on that interface is used instead. The updater rejects IPv4, loopback, link-local, and unique-local (`fc00::/7`) addresses.

If Ubuntu privacy addressing gives the server temporary IPv6 addresses, configure a stable address for the reverse proxy or set `IPV6_INTERFACE` after confirming that interface exposes the intended stable address first. The service can follow temporary addresses, but DNS would change more often than necessary.

## Behavior and safety

- Records must already exist; the service will not create or delete DNS records.
- Each configured name must resolve to exactly one Cloudflare AAAA record.
- A failure updating one record does not prevent attempts on the others.
- The API token is read from a root-owned file and is never logged.
- Stop the service with `sudo systemctl disable --now cloudflare-dns-updater`.
