import os
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from routes.auth import token_required
from database import get_db_connection
from services.rag_pipeline import rag_service
from services.detector import PromptInjectionDetector
from config import Config

docs_bp = Blueprint('docs', __name__)
detector = PromptInjectionDetector()

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@docs_bp.route('/upload', methods=['POST'])
@token_required
def upload_file(user_id, role):
    if 'file' not in request.files:
        return jsonify({"message": "No file part in the request"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Create a unique filename to prevent overrides
        unique_filename = f"{user_id}_{int(os.path.time()) if hasattr(os, 'time') else 12345}_{filename}"
        file_path = os.path.join(Config.UPLOAD_FOLDER, unique_filename)
        
        file.save(file_path)
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # 1. Insert file into database metadata
                cursor.execute(
                    "INSERT INTO documents (user_id, filename, file_path, status) VALUES (%s, %s, %s, %s)",
                    (user_id, filename, file_path, 'processing')
                )
                document_id = cursor.lastrowid
                conn.commit()
                
                # 2. Extract text and check for indirect injections in document content
                ext = os.path.splitext(filename)[1].lower()
                text = ""
                if ext == '.pdf':
                    text = rag_service.extract_text_from_pdf(file_path)
                elif ext in ['.docx', '.doc']:
                    text = rag_service.extract_text_from_docx(file_path)
                elif ext == '.txt':
                    text = rag_service.extract_text_from_txt(file_path)
                
                # Scan entire text for indirect injections or malicious instruction sets
                safety_report = detector.analyze(text, source="document")
                
                if safety_report["is_blocked"]:
                    # Log the attack in security logs
                    cursor.execute(
                        """INSERT INTO attack_logs 
                           (user_id, attack_type, payload, risk_score, severity, decision, explanation) 
                           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                        (user_id, "Indirect Injection", f"Document Upload: {filename} (Content flagged)", 
                         safety_report["risk_score"], safety_report["severity"], "Blocked", 
                         " || ".join(safety_report["explanations"]))
                    )
                    cursor.execute("UPDATE documents SET status = 'failed' WHERE id = %s", (document_id,))
                    conn.commit()
                    
                    # Delete the saved physical file
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        
                    return jsonify({
                        "message": "File upload blocked. Prompt injection or malicious instruction set detected inside the document content.",
                        "report": safety_report
                    }), 400
                
                # 3. If safe, chunk and generate embeddings
                num_chunks = rag_service.process_document(file_path, document_id, filename)
                
                # Update status to processed
                cursor.execute("UPDATE documents SET status = 'processed' WHERE id = %s", (document_id,))
                conn.commit()
                
                return jsonify({
                    "message": "File processed and indexed successfully!",
                    "document_id": document_id,
                    "filename": filename,
                    "chunks": num_chunks
                }), 201
                
        except Exception as e:
            conn.rollback()
            if os.path.exists(file_path):
                os.remove(file_path)
            return jsonify({"message": f"Failed to upload and process file: {str(e)}"}), 500
        finally:
            conn.close()
    else:
        return jsonify({"message": "Allowed file types are txt, pdf, docx"}), 400

@docs_bp.route('/', methods=['GET'])
@token_required
def get_documents(user_id, role):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Admins can view all documents, regular users view only their own
            if role == 'admin':
                cursor.execute(
                    """SELECT d.id, d.filename, d.upload_time, d.status, u.username 
                       FROM documents d JOIN users u ON d.user_id = u.id 
                       ORDER BY d.upload_time DESC"""
                )
            else:
                cursor.execute(
                    """SELECT id, filename, upload_time, status 
                       FROM documents WHERE user_id = %s 
                       ORDER BY upload_time DESC""", (user_id,)
                )
            docs = cursor.fetchall()
            return jsonify(docs), 200
    except Exception as e:
        return jsonify({"message": f"Database error: {str(e)}"}), 500
    finally:
        conn.close()

@docs_bp.route('/<int:doc_id>', methods=['DELETE'])
@token_required
def delete_document(user_id, role, doc_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Check ownership unless admin
            if role == 'admin':
                cursor.execute("SELECT * FROM documents WHERE id = %s", (doc_id,))
            else:
                cursor.execute("SELECT * FROM documents WHERE id = %s AND user_id = %s", (doc_id, user_id))
            
            doc = cursor.fetchone()
            if not doc:
                return jsonify({"message": "Document not found or unauthorized"}), 404
                
            # 1. Delete physical file
            if os.path.exists(doc['file_path']):
                try:
                    os.remove(doc['file_path'])
                except Exception as ex:
                    print(f"Error removing physical file: {ex}")
            
            # 2. Delete chunks from vector index
            rag_service.delete_document_chunks(doc_id)
            
            # 3. Delete database record
            cursor.execute("DELETE FROM documents WHERE id = %s", (doc_id,))
            conn.commit()
            
            return jsonify({"message": f"Document '{doc['filename']}' deleted successfully"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"message": f"Deletion failed: {str(e)}"}), 500
    finally:
        conn.close()
