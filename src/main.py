import os

from dotenv import load_dotenv
from google import genai


# Load environment variables
load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")

if not api_key:
    raise ValueError("GOOGLE_API_KEY was not found in the .env file.")

# Create Gemini client
client = genai.Client(api_key=api_key)


print("AI Portfolio Assistant")
print("Type 'exit' to quit.\n")


while True:
    user_message = input("You: ")

    if user_message.lower() == "exit":
        print("Goodbye!")
        break

    response = client.models.generate_content(
        model="gemini-3.8-flash",
        contents=user_message
    )

    print(f"\nAssistant: {response.text}\n")