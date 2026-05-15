# Publishing this claw as a public website

If the operator (or a user) asks you to expose your service publicly, follow
these steps. The platform handles the public ingress (Cloudflare Tunnel) — your
job is just to listen on the right address.

## 1. Pick a port

Choose a TCP port. The default is **3000**. Your service must listen on
**0.0.0.0** (all interfaces), not just `127.0.0.1`, otherwise the host
port-forward cannot reach it from outside the VM.

## 2. Start your service

Examples:

- Python static files: `python3 -m http.server 3000 --bind 0.0.0.0`
- Node.js: `app.listen(3000, '0.0.0.0')`
- Caddy file-server: `caddy file-server --listen 0.0.0.0:3000`
- Any framework: bind to `0.0.0.0:3000`, NOT `localhost:3000`

Keep the process running. If you exit, the public URL returns 502.

## 3. Tell the operator

Reply to the operator with something like:

> "I am ready. My service is listening on port 3000 (HTTP).
> To publish, please open the admin UI:
>   instances → this-claw → Add public site → app.<your-domain> → port 3000
> The site will be live in seconds."

## 4. What happens behind the scenes

When the operator clicks "Add public site":

1. The backend reserves a host port (range 24000-25999) and forwards traffic
   from that port to your `:3000`.
2. The cloudflared `config.yml` is regenerated with an ingress entry:
   `app.<their-domain>` → `http://127.0.0.1:<host-port>`.
3. cloudflared reloads and starts routing public traffic to you.

You don't need to do anything else.

## 5. Troubleshooting

- **502 Bad Gateway from the public URL**: your service exited or never bound
  to `0.0.0.0`. Restart it and confirm with `ss -tlnp | grep 3000`.
- **404 from the public URL**: the operator hasn't added the public site yet,
  or the cloudflared DNS record (CNAME) is missing.
- **Connection refused locally** (`curl http://127.0.0.1:3000` from inside the
  VM): your service is bound only to a different interface. Re-bind to `0.0.0.0`.

## 6. Stopping publication

The operator can revoke publication at any time from the same UI. The host
port-forward is removed and cloudflared stops routing the domain. Your service
inside the VM keeps running — only the public exposure goes away.
