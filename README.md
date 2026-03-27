# Sentinel — Password Audit Engine v4.0.0

A production-ready password security audit tool with breach detection, entropy analysis, and attack-time estimation.

---

## Features

- **k-Anonymity HIBP check** — Only the first 5 chars of the SHA-1 hash are sent. The full password never leaves the server.
- **Entropy calculation** — Based on character-set cardinality × password length.
- **Crack-time estimation** — Online (100 guesses/sec) and offline (1B guesses/sec) attack scenarios.
- **Pattern detection** — Repeated characters, keyboard walks, numeric-only, word+number suffix.
- **Common password list** — Supports a `common_passwords.txt` file (millions of entries) or falls back to an inline set.
- **Rate limiting** — slowapi, 20 audits/min per IP.
- **Security headers** — X-Content-Type-Options, X-Frame-Options, HSTS, etc.
- **Request tracing** — X-Request-ID and X-Response-Time on every response.
- **Environment config** — All settings via `.env` file (see below).

---

## Quick Start

```bash
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000` in your browser.

---

## Configuration (`.env`)

Create a `.env` file in the project root:

```env
HOST=0.0.0.0
PORT=8000
DEBUG=false

# Restrict CORS in production:
ALLOWED_ORIGINS=https://yourdomain.com

HIBP_TIMEOUT=6.0
HIBP_RETRIES=2

RATE_LIMIT_GLOBAL=60/minute
RATE_LIMIT_AUDIT=20/minute

COMMON_PASSWORDS_PATH=common_passwords.txt
LOG_LEVEL=INFO
```

---

## Common Password List

Download a large common-passwords list for better detection:

```bash
curl -L https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt \
  -o common_passwords.txt
```

---

## API Reference

### `POST /audit`

**Request:**
```json
{ "password": "yourpassword" }
```

**Response:**
```json
{
  "score": 5,
  "status": "Strong",
  "is_common": false,
  "is_pwned": false,
  "pwn_count": 0,
  "estimated_entropy_bits": 65.1,
  "crack_time_online": "CENTURIES",
  "crack_time_offline": "142 YEARS",
  "char_classes": { "lowercase": true, "uppercase": true, "digits": true, "symbols": false },
  "issues": [],
  "recommendations": ["Add special characters (!@#$%…)"]
}
```

### `GET /health`
Returns `{ "status": "ok", "version": "4.0.0" }`.

---

## Production Deployment

### Gunicorn + Uvicorn workers

```bash
pip install gunicorn
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

### Nginx reverse proxy (example)

```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Environment variables for production

| Variable | Recommended value |
|---|---|
| `ALLOWED_ORIGINS` | `https://yourdomain.com` |
| `DEBUG` | `false` |
| `LOG_LEVEL` | `WARNING` |
| `RATE_LIMIT_AUDIT` | `10/minute` |

---

## Security Notes

- Passwords are **never logged**. Only metadata (score, breach status) is logged at DEBUG level.
- The HIBP k-anonymity model ensures the plaintext password stays on the server.
- Set `ALLOWED_ORIGINS` to your exact domain before going live — the default `*` is for local development only.
- Run behind HTTPS in production to activate HSTS headers.

---

### Creater

<a href="https://instagram.com/its_.mayankbhatt" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/instagram.svg" alt="mayankbhatt2989" height="30" width="40" />Mayank Bhatt</a>
