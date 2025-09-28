import os
from dotenv import load_dotenv
from openai import OpenAI

# Load .env file automatically
load_dotenv()

def _client():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY not found. Add it to your .env file in project root."
        )
    return OpenAI(api_key=api_key)

_client_singleton = None

def complete(prompt: str, model="gpt-4o-mini"):
    global _client_singleton
    if _client_singleton is None:
        _client_singleton = _client()
    resp = _client_singleton.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.choices[0].message.content
