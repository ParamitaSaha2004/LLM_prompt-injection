from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from database import get_db_connection
from config import Config

auth_bp = Blueprint('auth', __name__)

def token_required(f):
    """Decorator to require JWT authentication on endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Check Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        
        try:
            data = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
            current_user_id = data['user_id']
            current_user_role = data['role']
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid!"}), 401
            
        return f(current_user_id, current_user_role, *args, **kwargs)
        
    return decorated

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({"message": "Missing registration details"}), 400
        
    username = data.get('username').strip()
    email = data.get('email').strip()
    password = data.get('password')
    role = data.get('role', 'user')  # Optional: default 'user' unless marked 'admin'
    
    if role not in ['user', 'admin']:
        role = 'user'

    password_hash = generate_password_hash(password)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check if user already exists
            cursor.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
            if cursor.fetchone():
                return jsonify({"message": "Username or Email already registered!"}), 400
                
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                (username, email, password_hash, role)
            )
            conn.commit()
            return jsonify({"message": "User registered successfully!"}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"message": f"Registration failed: {str(e)}"}), 500
    finally:
        conn.close()

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Missing credentials"}), 400

    username = data.get('username').strip()
    password = data.get('password')

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, username))
            user = cursor.fetchone()
            
            if not user or not check_password_hash(user['password_hash'], password):
                return jsonify({"message": "Invalid username or password"}), 401
                
            # Create JWT token
            token = jwt.encode({
                'user_id': user['id'],
                'role': user['role'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, Config.SECRET_KEY, algorithm='HS256')
            
            return jsonify({
                "token": token,
                "user": {
                    "id": user['id'],
                    "username": user['username'],
                    "email": user['email'],
                    "role": user['role']
                }
            }), 200
    except Exception as e:
        return jsonify({"message": f"Login failed: {str(e)}"}), 500
    finally:
        conn.close()

@auth_bp.route('/me', methods=['GET'])
@token_required
def get_me(user_id, role):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, username, email, role, created_at FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"message": "User not found!"}), 404
            return jsonify(user), 200
    except Exception as e:
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()
