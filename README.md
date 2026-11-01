# Invoice Summarizer

A small Flask service that turns invoice text into a short summary with an LLM.

## Setup

1. Create a virtual environment and install dependencies:

   ```bash
   python -m venv .venv
   .venv/Scripts/activate
   pip install -r requirements.txt
   ```

2. Copy the example configuration and fill in your own API key:

   ```bash
   cp config/credentials.example.txt config/credentials.txt
   ```

   The example file uses a placeholder value:

   ```text
   SERVICE_API_KEY=prod_REPLACE_WITH_YOUR_KEY
   ```

3. Start the service:

   ```bash
   python app.py
   ```

The service listens on `http://127.0.0.1:5000`. The `/health` endpoint returns
a simple status object, and `/summarize` reports whether the API key is
configured.

## Layout

- `app.py` — Flask application and the small credential loader.
- `config/credentials.example.txt` — safe template for local development.
- `config/credentials.txt` — local configuration, not intended for version control.
- `tests/test_app.py` — small unit tests for the credential loader.
