import os
from flask import Flask, jsonify
from flask_cors import CORS
from config import Config
from database import init_db
from routes.auth import auth_bp
from routes.docs import docs_bp
from routes.chat import chat_bp
from routes.playground import playground_bp
from routes.dashboard import dashboard_bp

app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS for frontend communications
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(docs_bp, url_prefix='/api/docs')
app.register_blueprint(chat_bp, url_prefix='/api/chat')
app.register_blueprint(playground_bp, url_prefix='/api/playground')
app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "PromptShield Backend API",
        "mock_llm_mode": Config.MOCK_LLM_MODE
    }), 200

# Error Handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"message": "Resource not found"}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({"message": "Internal server error"}), 500

if __name__ == '__main__':
    print("Initializing Database...")
    try:
        init_db()
    except Exception as e:
        print(f"Database initialization deferred or failed: {e}. Ensure MySQL is running.")
        
    print("Starting Flask web server on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=True)
