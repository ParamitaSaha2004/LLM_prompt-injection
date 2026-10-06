from google import genai
from config import Config

client = genai.Client(api_key=Config.GEMINI_API_KEY)

response = client.models.generate_content(
    model="models/gemini-flash-latest",
    contents="Say hello."
)

print(response.text)