# Port Registry

Central reference for all ports used by theyOS.
All host ports are configurable via `.env` — change them if another project conflicts.

## Infrastructure (fixed per stack)

| Env var              | Default | Bound to    | Service              | Notes                        |
|----------------------|---------|-------------|----------------------|------------------------------|
| `CADDY_HTTP_PORT`    | 8080    | 0.0.0.0     | Caddy HTTP           | Tailscale + Cloudflare entry |
| `CADDY_HTTPS_PORT`   | 8443    | 0.0.0.0     | Caddy HTTPS          |                              |
| `ADMIN_PORT`         | 8892    | 127.0.0.1   | Rust admin panel     | Direct access / healthcheck  |

## Dynamic claw instances

Firecracker VMs get SSH ports allocated dynamically in the 22000–23999 range.
Public claw sites on Linux/Firecracker use host forwards allocated dynamically
in the 24000–25999 range. Public site assignments are stored in SQLite in the
`public_sites` table and exposed locally only on `127.0.0.1`.

## System services (not managed by theyOS)

| Port  | Service             | Notes                        |
|-------|---------------------|------------------------------|
| 22    | SSH                 | `networking.firewall` allows |
| 2000  | cloudflared metrics | `curl localhost:2000/ready`  |

## Running two stacks side by side

If you need `theyos` and another project (e.g. `soyeht-distro`) on the same machine:

```env
# theyos/.env  — shift all ports up by 10
CADDY_HTTP_PORT=8090
CADDY_HTTPS_PORT=8453
ADMIN_PORT=8902
```
