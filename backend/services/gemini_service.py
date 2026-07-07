from google import genai
from config import Config


class GeminiService:

    def __init__(self):
        self.client = genai.Client(api_key=Config.GEMINI_API_KEY)

    def ask(self, prompt):

        try:

            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )

            return response.text

        except Exception as e:

            import traceback

            print("=" * 80)
            print("GEMINI ERROR")
            traceback.print_exc()
            print("=" * 80)

            return f"Gemini Error: {str(e)}"
            

gemini = GeminiService()


def ask_gemini(prompt):
    return gemini.ask(prompt)