# Public Claw Sites

Public claw sites let one claw instance serve a user-owned public domain without
exposing the theyOS admin panel.

## Flow

1. Start the claw instance.
2. Register one or more domains for the instance:

   ```bash
   curl -X POST http://localhost:8892/api/v1/instances/inst-id/public-sites \
     -H 'Content-Type: application/json' \
     -b 'soyeht_session=...' \
     -d '{"domain":"example.com","guest_port":3000}'
   ```

3. Point the public domain at Caddy through Cloudflare DNS or Cloudflare Tunnel.

The `guest_port` defaults to `3000`. Multiple domains can be registered with
`{"domains":["example.com","www.example.com"],"guest_port":3000}`.

## Routing

Caddy remains the local HTTP router. Admin hosts, localhost, LAN, Tailscale, and
known admin domains continue to proxy normally to the backend.

Public/custom hosts are proxied to the backend with:

```http
X-TheyOS-Public-Site: 1
```

When that marker is present, the backend looks up the request `Host` in the
`public_sites` table. If a matching enabled site exists for an active instance,
the backend reverse-proxies to that VM target. If no mapping exists, it returns
404 and does not serve the admin SPA/API.

## VM Targets

Linux/Firecracker instances use slirp host forwards:

- host target: `127.0.0.1:<allocated-port>`
- allocated port range: `24000-25999`
- guest target: `10.0.2.100:<guest_port>`

macOS/VZ instances use the instance `vm_ip` directly:

- target: `http://<vm_ip>:<guest_port>`
- the site inside the VM must listen on `0.0.0.0:<guest_port>`, not only
  `127.0.0.1`.

## Cloudflare

Cloudflare can be DNS-only, proxied DNS, or Cloudflare Tunnel. For Tunnel,
add one ingress entry per custom domain pointing to `http://localhost:8080`.
See `distro/cloudflared/config.yml.example`.

Do not point public claw domains at the admin hostname. Caddy and the backend
public-site marker keep unknown public hosts closed with 404.

When you POST a new domain, the response includes `cloudflared_warning` if
the domain has no matching `ingress` entry in the cloudflared config (default
path: `distro/cloudflared/config.yml`, override via `THEYOS_CLOUDFLARED_CONFIG`).
The check is best-effort — the warning is suppressed entirely when the file
can't be read (typical for DNS-only / proxied-DNS deployments without a
tunnel).

## Tailscale-only hosts (no Caddy)

When `services.theyos.accessMode = "tailscale"`, Caddy is not enabled and the
gateway middleware is not in the request path. Public sites still work — the
admin backend writes a complete `cloudflared/config.yml` with one `ingress`
entry per public site, pointing cloudflared **directly** at the host port
forward (`http://127.0.0.1:24XXX`). cloudflared reloads on every change.

Other claws stay invisible to the internet because cloudflared only routes
hostnames listed in its `ingress`. No port is opened on the host.

See [`public-claw-sites-cloudflared.md`](public-claw-sites-cloudflared.md) for
the one-time Cloudflare account / tunnel / DNS setup.

## macOS Caddy

On NixOS, Caddy is declared in `nix/module.nix` and managed by systemd. On
macOS, soyeht installs and supervises Caddy through a per-user LaunchAgent and
a local CA in the System keychain. See [`caddy-macos.md`](caddy-macos.md) for
the full lifecycle (install, status, reload, uninstall) and what theyOS does —
or refuses to do — to your Mac.

For dev iteration, you can register a public site against a `.localhost`
hostname so Caddy serves it on `https://app.localhost` via the local CA, no
DNS or Cloudflare required:

```bash
curl -X POST http://localhost:8892/api/v1/instances/<id>/public-sites \
  -H 'Content-Type: application/json' \
  -b 'soyeht_session=...' \
  -d '{"domain":"app.localhost","guest_port":3000}'
```
