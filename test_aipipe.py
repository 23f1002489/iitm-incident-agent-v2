
import os
import httpx
from dotenv import load_dotenv

load_dotenv(override=True)

token = os.getenv("AI_PIPE_TOKEN", "").strip()
model = os.getenv("AI_PIPE_MODEL", "openai/gpt-4.1-nano")
url = os.getenv(
    "AI_PIPE_CHAT_URL",
    "https://aipipe.org/openrouter/v1/chat/completions"
)


if not token:
    raise RuntimeError("AI_PIPE_TOKEN is missing")

with httpx.Client(timeout=20, trust_env=False) as client:
    response = client.post(
        url,
        headers={"Authorization": f"Bearer {token}"},
        json={
            "model": model,
            "temperature": 0,
            "messages": [
                {"role": "user", "content": "Reply with OK"}
            ]
        }
    )

# response = httpx.post(
#     url,
#     headers={
#         "Authorization": f"Bearer {token}",
#         "Content-Type": "application/json"
#     },
#     json={
#         "model": model,
#         "messages": [
#             {"role": "user", "content": "Reply with OK"}
#         ],
#         "max_tokens": 20
#     },
#     timeout=20
# )

print("HTTP status:", response.status_code)

if response.is_success:
    print("Model response:", response.json()["choices"][0]["message"]["content"])
else:
    print("AI Pipe request failed")
