# GuardianAI API

**The Security Layer for AI Systems** — by Neuronium Engineers

Detects prompt injection, jailbreaks, deepfakes, and adversarial attacks in real time.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | /v1/health | No | Health check |
| GET | /v1/info | Yes | Engine info + usage |
| POST | /v1/scan/input | Yes | Scan user input |
| POST | /v1/scan/output | Yes | Filter LLM output |

## Base URL

```
https://guardianai-api.onrender.com
```

## Authentication

```
Authorization: Bearer your_api_key
```

## Quick start

```python
import requests

res = requests.post(
    "https://guardianai-api.onrender.com/v1/scan/input",
    headers={"Authorization": "Bearer your_key"},
    json={"text": "Ignore all previous instructions...", "use_semantic": True}
)
print(res.json())
```

## Architecture

- **Layer 1 (Pattern)** — 19 regex patterns, <5ms
- **Layer 2 (Semantic)** — LLM-powered judge, ~50ms
- **Output Filter** — PII + credential detection, <2ms

## License

Apache 2.0 · Built by [Neuronium Engineers](https://neuronium.engineer) · Frankfurt am Main
