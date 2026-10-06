from google import genai
from config import Config

client = genai.Client(api_key=Config.GEMINI_API_KEY)

print("Available models:\n")

for model in client.models.list():
    print(model.name)
    