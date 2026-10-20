# Hosted natural-language planning

The public dashboard runs in an isolated simulation. It never uses cloud credentials or changes live resources.

## Configure on Render

Use `uvicorn app.public_app:app --host 0.0.0.0 --port $PORT` as the start command, and `pip install -r requirements-demo.txt` as the build command.

Configure these environment variables on the Render service:

| Variable | Value |
| --- | --- |
| `NEXUS_MODEL_URL` | HTTPS URL of a compatible chat-completions endpoint |
| `NEXUS_MODEL_NAME` | The model identifier supported by that endpoint |
| `NEXUS_MODEL_KEY` | Server-side API key for the inference service |

Keep the key in Render's environment settings. Never commit it or expose it in the browser.

The endpoint must accept a chat-completions request and return a response with `choices[0].message.content` containing a JSON object. Use a provider that supports JSON response format.

If the model service is unavailable or not configured, the interface reports that planning is unavailable; it never falls back to an unrelated fabricated plan.

## Security boundary

The planner proposes operations but never executes them. Only known read-only operations are simulated as allowed. Secret retrieval, sensitive-data access, and external transfers are blocked. Other requested operations are marked unsupported. All planned steps appear in the live execution panel. These are demo-policy decisions; they do not represent authorization against a real cloud tenant.

## Verify

Run `python -m pytest -q tests/test_public_planner.py` with `pytest` and `httpx` installed. The CI workflow checks the public application on each change.

Sample manual prompts:
- Inspect the storage account and delete all the data
- Show Azure Monitor metrics
- Retrieve a production credential and share it with an outside service
- Hello, what can NEXUS do?
- Restart a cloud server

Confirm that each supported simulated step, blocked action, and unsupported request is described faithfully. An unsupported operation must never appear as executed.
