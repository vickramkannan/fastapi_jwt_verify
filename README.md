# FastAPI RS256 JWT verification

## Deploy on Render
1. Upload `main.py`, `requirements.txt`, and `render.yaml` to the root of a GitHub repository.
2. In Render, choose **New + → Blueprint** and connect the repository.
3. Deploy and wait for the service to become live.
4. Submit the full URL `https://YOUR-SERVICE.onrender.com/verify`.

The endpoint accepts `POST /verify` with JSON `{"token":"..."}`. It validates RS256 signature, exact issuer, exact audience, and expiry using the supplied public key. It requires `exp`, `iss`, `aud`, `sub`, and `email`. Invalid tokens return HTTP 401 with `{"detail":{"valid":false}}`.

## Local test
```bash
pip install -r requirements.txt
uvicorn main:app --reload
```
