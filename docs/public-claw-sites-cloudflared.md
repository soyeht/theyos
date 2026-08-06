# Public Claw Sites via Cloudflare Tunnel

This is the path used on **tailscale-only hosts** (`accessMode = "tailscale"`)
where there is no public IP / open port and Caddy is not enabled.

The admin backend manages cloudflared end-to-end: it generates the ingress
`config.yml`, writes it atomically, and reloads cloudflared on every public
site add/remove. No manual YAML editing is needed after the one-time setup.

---

## When to use this path

| Situation | Use Cloudflare Tunnel? | Why |
|---|---|---|
| Host has a public IP and a domain | No — use Caddy (`accessMode = "domain"`) | Caddy can terminate TLS directly |
| Host is behind NAT / no public IP | **Yes** | Tunnel is outbound — no port forwarding needed |
| Host is tailscale-only by choice | **Yes** | Keeps admin private to the tailnet, exposes only what you publish |

---

## One-time setup (operator, ~5 min)

### 1. Cloudflare account + named tunnel

1. Sign up for a free Cloudflare account at https://cloudflare.com.
2. Add a domain you control (use the dashboard wizard — moves nameservers).
3. Open **Zero Trust → Networks → Tunnels → Create a tunnel**.
4. Choose `Cloudflared` connector type, name it (e.g. `theyos-devs`), copy
   the connector token shown on the next page. **Don't close this tab yet.**

### 2. Save the token on the host

```sh
ssh devs
sudo mkdir -p /var/lib/cloudflared && sudo chown $USER:users /var/lib/cloudflared && sudo chmod 700 /var/lib/cloudflared
echo "PASTE_TOKEN_HERE" | sudo tee /var/lib/cloudflared/token
sudo chmod 600 /var/lib/cloudflared/token
sudo chown $USER:users /var/lib/cloudflared/token   # owner = cfg.user (cloudflared runs as that)
```

The default `cfg.cloudflare.tokenFile` is `/var/lib/cloudflared/token`. The
file must be readable by `cfg.user` because `cloudflared.service` runs as
that user. Do not put the token in `cfg.secretsDir` — that directory is
chowned to the `soyeht` service account on every rebuild and would lock
cloudflared out.

### 3. Enable in `nix/host.nix`

```nix
services.theyos.cloudflare.enable = true;
# tokenFile and configFile have sensible defaults — only override if needed.
```

Then deploy:

```sh
sudo soyeht update
```

This creates `/var/lib/theyos/cloudflared/config.yml` (empty/`404` only),
starts the `cloudflared.service`, and wires the admin backend env vars
(`THEYOS_CLOUDFLARED_CONFIG` and `THEYOS_CLOUDFLARED_RELOAD_CMD`).

### 4. Sanity check

```sh
sudo systemctl status cloudflared    # Active: running
journalctl -u cloudflared -n 50      # should show "Registered tunnel connection"
```

---

## Per-domain setup (operator, ~30s each)

For every domain you want to publish, create a CNAME record in Cloudflare DNS:

| Type  | Name              | Target                              | Proxy |
|-------|-------------------|-------------------------------------|-------|
| CNAME | app               | `<tunnel-id>.cfargotunnel.com`     | ON    |

Find `<tunnel-id>` in the Zero Trust dashboard → your tunnel → "Public
hostname" tab, or in the URL of the tunnel page.

CNAME for a wildcard works too (`*.your-domain.com`) if you want to publish
many subdomains under one tunnel without per-domain DNS edits.

---

## Per-publish (zero-touch)

After the one-time setup is done:

1. Open the admin UI → **Instances → \<your claw\> → Add public site**.
2. Type the domain (e.g. `app.your-domain.com`) and the guest port (default
   `3000`).
3. Click "Add". The site is live in seconds.

Behind the scenes, the backend:

1. Reserves a host port from `24000-25999` and creates the slirp4netns
   forward `host:<port> → VM:<guest_port>`.
2. Writes the new ingress entry to `/var/lib/theyos/cloudflared/config.yml`
   atomically:
   ```yaml
   ingress:
     - hostname: app.your-domain.com
       service: http://127.0.0.1:24042
     - service: http_status:404
   ```
3. Calls `sudo systemctl reload cloudflared` (NOPASSWD-allowed for the
   `soyeht` service user, see `nix/module.nix`).

cloudflared reloads its ingress without dropping the tunnel connection
(SIGHUP, ~1s).

---

## Removing a public site

UI → **Instances → \<claw\> → Public Sites → remove**.

The backend deletes the row, regenerates `config.yml` without the entry, and
reloads cloudflared. The public URL returns 404 from cloudflared after that.

---

## Isolation guarantees

- Other claws on the same host have **different host ports**. Those ports
  are **not** in the cloudflared ingress, so they are unreachable from the
  internet.
- The host has **no inbound port open**. Cloudflared connects out to
  Cloudflare Edge — there is nothing to scan.
- The admin API stays on Tailscale (or whatever your `accessMode` dictates).
  It is never exposed via the tunnel because the backend never adds an
  ingress entry for it.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| "Cloudflared service failed to start" | `sudo systemctl status cloudflared && journalctl -u cloudflared -n 50`. Most common: token file missing or wrong perms. |
| Public URL returns 502 | The VM service exited or never bound to `0.0.0.0`. SSH into the claw, `ss -tlnp \| grep <guest_port>`. |
| Public URL returns 404 from cloudflared | The CNAME is missing in Cloudflare DNS, or the public site was just removed. |
| `config.yml` not regenerated after adding a site | Check `journalctl -u soyeht-admin-host -g cloudflared-sync`. Most likely the env var `THEYOS_CLOUDFLARED_CONFIG` isn't set on the admin service (verify with `systemctl show soyeht-admin-host -p Environment`). |
| Backend can't reload cloudflared | `sudo -u soyeht sudo -n systemctl reload cloudflared` should succeed. If it prompts for password, the sudoers rule isn't matching — verify `cfg.cloudflare.enable = true` is in your host.nix and you've redeployed. |

---

<!-- A "What's not in this MVP" backlog stood here until 2026-08-06 (auto-CNAME
     via the Cloudflare API, and others). Removed with the rest of the planning
     corpus: this document describes the tunnel as it works today. -->
