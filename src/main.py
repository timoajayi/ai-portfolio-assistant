"""Interactive CLI using the same durable paid-operation gate as the API."""

from dotenv import load_dotenv
from google import genai
import os

from src.config import Settings
from src.provider import http_options
from src.usage import paid_call


def generate_answer(message):
    settings = Settings.from_env()

    def operation():
        client = genai.Client(api_key=os.environ.get("GOOGLE_API_KEY"),
                              http_options=http_options(settings.generation_timeout_ms,
                                                        network_policy=settings.gemini_network_policy))
        try:
            return client.models.generate_content(
                model="gemini-3.8-flash", contents=message,
                config={"automatic_continuation": False,
                        "max_output_tokens": settings.max_output_tokens,
                        "thinking_config": {"thinking_level": settings.thinking_level}},
            )
        finally:
            client.close()

    return paid_call("generation", operation)


def main():
    load_dotenv()
    print("AI Portfolio Assistant\nType 'exit' to quit.\n")
    while True:
        message = input("You: ")
        if message.lower() == "exit":
            print("Goodbye!")
            return
        try:
            response = generate_answer(message)
            print(f"\nAssistant: {response.text}\n")
        except Exception:
            print("The AI assistant could not generate a response.")


if __name__ == "__main__":
    main()
