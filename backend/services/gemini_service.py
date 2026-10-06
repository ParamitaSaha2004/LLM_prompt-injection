# from google import genai
# from config import Config


# class GeminiService:

#     def __init__(self):
#         self.client = genai.Client(api_key=Config.GEMINI_API_KEY)

#     def ask(self, prompt):

#         try:

#             response = self.client.models.generate_content(
#                 model="gemini-2.5-flash",
#                 contents=prompt
#             )

#             return response.text

#         except Exception as e:

#                 import traceback

#                 print("=" * 80)
#                 print("GEMINI ERROR")
#                 traceback.print_exc()
#                 print("=" * 80)

#                 error = str(e)

#                 if "RESOURCE_EXHAUSTED" in error or "429" in error:
#                     return (
#                         "Gemini API quota exceeded. "
#                         "Please try again later or configure another API key."
#                     )

#                 return "Unable to contact Gemini."


# def ask_gemini(prompt):
#     return gemini.ask(prompt)

from google import genai
from config import Config
import traceback


class GeminiService:

    def __init__(self):
        self.client = genai.Client(api_key=Config.GEMINI_API_KEY)

    def ask(self, prompt):
        try:
            MODEL_NAME = "models/gemini-flash-latest"

            print("=" * 60)
            print("Using Gemini model:", MODEL_NAME)
            print("Prompt length:", len(prompt))
            print("Prompt preview:")
            print(prompt[:300])
            print("=" * 60)

            response = self.client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt
            )

            print("=" * 60)
            print("Gemini response:")
            print(response.text[:300])
            print("=" * 60)

            return response.text

        except Exception as e:
            print("=" * 80)
            print("GEMINI ERROR")
            traceback.print_exc()
            print("=" * 80)

            error = str(e)

            if "NOT_FOUND" in error:
                return "Configured Gemini model was not found."

            if "RESOURCE_EXHAUSTED" in error or "429" in error:
                return (
                    "Gemini API quota exceeded. "
                    "Please wait for the quota to reset or use another API key."
                )

            return f"Gemini Error: {error}"


# Create one global Gemini client
gemini = GeminiService()


def ask_gemini(prompt):
    return gemini.ask(prompt)