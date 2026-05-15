# soyeht admin panel

Local stack (fast + secure):
- Backend: Rust (`axum`, sessions via `HttpOnly` cookie)
- Frontend: React + TypeScript + Vite

## Structure

- `rust/`     Rust workspace (server + IPC subprocesses)
- `frontend/` React/Vite app source
- `web/`      Compiled frontend (Vite build output — served by Rust)
- `scripts/`  dev, rebuild, doctor helpers

## Run locally

### 1) Backend

```bash
cd rust
cargo build -p server-rs
WEB_DIR=../web ADDR=:8892 ./target/debug/server
```

Backend runs on `http://localhost:8892`.

### 2) Frontend (dev with hot-reload)

```bash
cd frontend
npm install
npm run dev
```

Frontend dev server runs on `http://localhost:5173` and proxies API calls to `:8892`.

### Using scripts

```bash
admin/scripts/rebuild   # cargo build -p server-rs
admin/scripts/dev       # run the compiled server binary
admin/scripts/doctor    # check toolchain prerequisites
```

## Local login

- username: `admin`
- password: set via `SOYEHT_ADMIN_PASSWORD` env var

## Main endpoints

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET  /api/v1/me`
- `GET/POST /api/v1/instances`
- `POST /api/v1/instances/{id}/actions/{action}`
- `GET  /api/v1/logs`
- `GET  /api/v1/terminals/containers`
- `GET  /api/v1/terminals/{container}/stream`
- `POST /api/v1/terminals/{container}/command`
- `POST /api/v1/terminals/{container}/restart`
