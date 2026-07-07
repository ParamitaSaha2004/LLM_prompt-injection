# import os
# from dotenv import load_dotenv


# # Load environment variables from .env file
# load_dotenv()

# class Config:
#     SECRET_KEY = os.getenv("JWT_SECRET", "super_secret_jwt_key_promptshield_2026")
#     MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
#     MYSQL_USER = os.getenv("MYSQL_USER", "root")
#     MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
#     MYSQL_DB = os.getenv("MYSQL_DB", "promptshield")
#     GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
#     UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", os.path.join(os.path.dirname(__file__), "uploads"))
#     VECTOR_DB_PATH = os.getenv("VECTOR_DB_PATH", os.path.join(os.path.dirname(__file__), "vector_store.faiss"))
#     # If Mock LLM Mode is True, we simulate Gemini responses instead of querying API
#     # But if a GEMINI_API_KEY is provided, we disable mock mode automatically.
#     _mock_mode_env = os.getenv("MOCK_LLM_MODE", "True").lower() == "true"
#     MOCK_LLM_MODE = False if GEMINI_API_KEY else _mock_mode_env

#     # Ensure uploads directory exists
#     os.makedirs(UPLOAD_FOLDER, exist_ok=True)

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    SECRET_KEY = os.getenv(
        "JWT_SECRET",
        "super_secret_jwt_key_promptshield_2026"
    )

    MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
    MYSQL_USER = os.getenv("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
    MYSQL_DB = os.getenv("MYSQL_DB", "promptshield")

    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

    UPLOAD_FOLDER = os.getenv(
        "UPLOAD_FOLDER",
        os.path.join(os.path.dirname(__file__), "uploads")
    )

    VECTOR_DB_PATH = os.getenv(
        "VECTOR_DB_PATH",
        os.path.join(os.path.dirname(__file__), "vector_store.faiss")
    )

    # Automatically disable Mock Mode if a Gemini API key is available
    _mock_mode_env = os.getenv("MOCK_LLM_MODE", "True").lower() == "true"
    MOCK_LLM_MODE = False if GEMINI_API_KEY else _mock_mode_env

# Ensure uploads directory exists
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
