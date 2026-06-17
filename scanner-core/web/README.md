# Web Frontend Development

This directory contains the development tooling for bjorn2scan's web UI. The actual static files (HTML/CSS) are in `../static/`.

## Quick Start for Local Development

For rapid frontend iteration without rebuilding the backend:

### 1. Start Backend Port-Forward

```bash
# From project root
./scripts/port-forward

# OR manually:
kubectl port-forward svc/bjorn2scan 8080:80 -n <namespace>
```

### 2. Run Local Frontend Server

```bash
# From project root OR scripts folder
./scripts/run-local-frontend
```

### 3. Access Frontend

Open your browser to: **http://localhost:9000**

## How It Works

The `run-local-frontend` script:
- Runs nginx in a Docker container
- Mounts the `scanner-core/static/` directory for live HTML editing
- Proxies API calls (`/api/*`, `/health`, `/info`) to `localhost:8080` (your port-forwarded backend)
- Serves the frontend on `http://localhost:9000`

## Development Workflow

1. Start port-forward to your backend (once)
2. Run `./scripts/run-local-frontend` (once)
3. Edit HTML/CSS files in `scanner-core/static/`
4. Refresh browser to see changes (no rebuild needed!)
5. Press Ctrl+C to stop the frontend server

## Directory Structure

- **../static/** - Production HTML/CSS files (embedded into Go binary)
  - `index.html` - Main dashboard
  - `images.html` - Images page with filtering/pagination
  - `sql.html` - SQL debug console
  - `*.css` - Stylesheets
- **This directory (web/)** - Development tooling only
  - `dev-nginx.conf` - Nginx configuration for local development
  - `package.json` - npm dependencies for linting
  - Linter configurations (.eslintrc.json, .stylelintrc.json, .htmlhintrc)

## Production

In production, these HTML files are:
1. Embedded into the Go binary using `//go:embed`
2. Served directly by the k8s-scan-server or bjorn2scan-agent
3. No separate nginx needed

## Troubleshooting

**"Connection refused" errors:**
- Ensure backend port-forward is running on localhost:8080
- Check: `curl http://localhost:8080/health`

**"Cannot connect to the Docker daemon":**
- Ensure Docker Desktop is running

**Changes not appearing:**
- Hard refresh browser (Cmd+Shift+R on Mac, Ctrl+Shift+R on Windows/Linux)
- Files are mounted read-only, so changes should be instant

## Code Linting

### Prerequisites

- Node.js 18+ and npm

### Setup

Install linting dependencies:

```bash
npm install
```

### Running Linters

Lint all files (HTML, CSS, JavaScript):
```bash
npm run lint
```

Lint specific file types:
```bash
npm run lint:html    # Lint HTML files
npm run lint:css     # Lint CSS files
npm run lint:js      # Lint JavaScript in HTML files
```

Auto-fix CSS issues:
```bash
npm run lint:fix
```

### Configuration Files

- `.eslintrc.json` - JavaScript/ESLint configuration
- `.stylelintrc.json` - CSS/stylelint configuration
- `.htmlhintrc` - HTML/HTMLHint configuration

### Integration

Web linting is integrated into:
- Local testing: `scripts/test_local`
- CI/CD: `.github/workflows/ci.yaml` (web-lint job)
