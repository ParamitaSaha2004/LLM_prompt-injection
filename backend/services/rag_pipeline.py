import os
import re
import json
import numpy as np
import pdfplumber
import PyPDF2
from docx import Document

# Fallback-safe imports
try:
    from sentence_transformers import SentenceTransformer
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False

try:
    import faiss
    HAS_FAISS = True
except ImportError:
    HAS_FAISS = False

class SimpleNumpyIndex:
    """A pure-numpy fallback for FAISS vector index."""
    def __init__(self, dimension):
        self.dimension = dimension
        self.vectors = []
        self.metadata = []

    def add(self, vectors, metadata_list):
        if len(vectors) == 0:
            return
        self.vectors.extend(vectors)
        self.metadata.extend(metadata_list)

    def search(self, query_vector, k=3):
        if not self.vectors:
            return [], []
        
        q_vec = np.array(query_vector).reshape(1, -1)
        vecs = np.array(self.vectors)
        
        # Calculate cosine similarity
        q_norm = np.linalg.norm(q_vec, axis=1, keepdims=True)
        vecs_norm = np.linalg.norm(vecs, axis=1, keepdims=True)
        
        # Handle zero division
        q_norm[q_norm == 0] = 1e-10
        vecs_norm[vecs_norm == 0] = 1e-10
        
        sims = np.dot(q_vec, vecs.T) / (q_norm * vecs_norm.T)
        sims = sims[0]
        
        # Get top k indices
        top_k_idx = np.argsort(sims)[::-1][:k]
        
        results_meta = [self.metadata[idx] for idx in top_k_idx]
        results_scores = [float(sims[idx]) for idx in top_k_idx]
        
        return results_scores, results_meta

    def save(self, filepath):
        data = {
            "vectors": [v.tolist() for v in self.vectors],
            "metadata": self.metadata
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def load(self, filepath):
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.vectors = [np.array(v) for v in data["vectors"]]
                self.metadata = data["metadata"]


class RAGPipeline:
    def __init__(self, vector_db_path="vector_store.faiss"):
        self.vector_db_path = vector_db_path
        self.metadata_path = vector_db_path + ".meta"
        self.model = None
        self.dimension = 384  # Default for all-MiniLM-L6-v2
        
        if HAS_TRANSFORMERS:
            try:
                # Load sentence transformer model
                self.model = SentenceTransformer('all-MiniLM-L6-v2')
            except Exception as e:
                print(f"Error loading SentenceTransformer: {e}")
                
        # Initialize vector store
        if HAS_FAISS:
            print("Using FAISS vector store.")
            self.index = faiss.IndexFlatIP(self.dimension)
            self.metadata = []
        else:
            print("FAISS not available. Using pure Numpy fallback vector store.")
            self.index = SimpleNumpyIndex(self.dimension)
            self.metadata = []

        self.load_index()

    def extract_text_from_pdf(self, file_path):
        """Extract text from a PDF file using pdfplumber with PyPDF2 fallback."""
        text = ""
        try:
            with pdfplumber.open(file_path) as pdf:
                for page in pdf.pages:
                    extracted = page.extract_text()
                    if extracted:
                        text += extracted + "\n"
        except Exception as e:
            print(f"pdfplumber failed: {e}. Trying PyPDF2...")
            try:
                with open(file_path, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    for page in reader.pages:
                        extracted = page.extract_text()
                        if extracted:
                            text += extracted + "\n"
            except Exception as ex:
                print(f"PyPDF2 also failed: {ex}")
        return text

    def extract_text_from_docx(self, file_path):
        """Extract text from a DOCX file."""
        text = ""
        try:
            doc = Document(file_path)
            for para in doc.paragraphs:
                text += para.text + "\n"
        except Exception as e:
            print(f"DOCX extraction failed: {e}")
        return text

    def extract_text_from_txt(self, file_path):
        """Extract text from a plain TXT file."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception as e:
            print(f"TXT extraction failed: {e}")
            return ""

    def chunk_text(self, text, chunk_size=500, overlap=100):
        """Split text into manageable chunks with overlap."""
        # Clean whitespaces
        text = re.sub(r'\s+', ' ', text).strip()
        chunks = []
        start = 0
        while start < len(text):
            end = start + chunk_size
            chunks.append(text[start:end])
            start += chunk_size - overlap
        return chunks

    def process_document(self, file_path, document_id, filename):
        """Parse file, generate chunks, generate embeddings, and insert into Index."""
        ext = os.path.splitext(filename)[1].lower()
        if ext == '.pdf':
            text = self.extract_text_from_pdf(file_path)
        elif ext in ['.docx', '.doc']:
            text = self.extract_text_from_docx(file_path)
        elif ext == '.txt':
            text = self.extract_text_from_txt(file_path)
        else:
            raise ValueError(f"Unsupported file extension: {ext}")

        if not text.strip():
            raise ValueError("No text could be extracted from the file.")

        chunks = self.chunk_text(text)
        
        # If SentenceTransformer failed to load, use a mock/hashed embedding helper
        if self.model is None:
            embeddings = [self._get_mock_embedding(chunk) for chunk in chunks]
        else:
            embeddings = self.model.encode(chunks, show_progress_bar=False)
            # Normalize embeddings for Inner Product (Cosine similarity)
            embeddings = [e / np.linalg.norm(e) for e in embeddings]

        # Structure metadata
        chunk_metas = []
        for i, chunk in enumerate(chunks):
            chunk_metas.append({
                "document_id": document_id,
                "filename": filename,
                "chunk_index": i,
                "text": chunk
            })

        # Save to index
        if HAS_FAISS:
            self.index.add(np.array(embeddings).astype('float32'))
            self.metadata.extend(chunk_metas)
        else:
            self.index.add(embeddings, chunk_metas)
            self.metadata = self.index.metadata

        self.save_index()
        return len(chunks)

    def _get_mock_embedding(self, text):
        """Generate a deterministic mock embedding vector based on hash (fallback)."""
        np.random.seed(abs(hash(text)) % 2**32)
        vec = np.random.randn(self.dimension)
        return (vec / np.linalg.norm(vec)).tolist()

    def search_similar_chunks(self, query, k=3):
        
        print("=" * 60)
        print("RAG SEARCH")
        print("Query:", query)
        print("Total indexed chunks:", len(self.metadata))
        print("=" * 60)
        
        """Retrieve the top k similar text chunks from the vector database."""
        if not self.metadata:
            
            return []

        if self.model is None:
            query_vector = self._get_mock_embedding(query)
        else:
            query_vector = self.model.encode([query])[0]
            query_vector = query_vector / np.linalg.norm(query_vector)

        if HAS_FAISS:
            q_vec = np.array([query_vector]).astype('float32')
            scores, indices = self.index.search(q_vec, k)
            
            results = []
            for i, idx in enumerate(indices[0]):
                if idx != -1 and idx < len(self.metadata):
                    meta = self.metadata[idx].copy()
                    meta['score'] = float(scores[0][i])
                    results.append(meta)
            return results
        else:
            scores, metas = self.index.search(query_vector, k)
            results = []
            for i, meta in enumerate(metas):
                meta_copy = meta.copy()
                meta_copy['score'] = scores[i]
                results.append(meta_copy)
            return results
     
        

    def delete_document_chunks(self, document_id):
        """Remove chunks matching a document_id from memory and reload/rebuild index."""
        # Find which chunks to keep
        keep_indices = [i for i, meta in enumerate(self.metadata) if meta['document_id'] != document_id]
        
        if len(keep_indices) == len(self.metadata):
            return # Nothing to delete

        # Re-initialize index and repopulate
        if HAS_FAISS:
            # FAISS IndexFlat doesn't easily support dynamic index deletion by metadata.
            # So we rebuild the index from the saved metadata we are keeping.
            # However, since we don't store vectors in metadata, we extract vectors from original index first.
            original_vectors = [self.index.reconstruct(i) for i in keep_indices]
            
            self.index = faiss.IndexFlatIP(self.dimension)
            self.metadata = [self.metadata[i] for i in keep_indices]
            
            if original_vectors:
                self.index.add(np.array(original_vectors).astype('float32'))
        else:
            # For numpy, just filter in SimpleNumpyIndex
            new_vectors = [self.index.vectors[i] for i in keep_indices]
            new_metadata = [self.index.metadata[i] for i in keep_indices]
            
            self.index.vectors = new_vectors
            self.index.metadata = new_metadata
            self.metadata = new_metadata

        self.save_index()

    def save_index(self):
        """Persist index and metadata files."""
        try:
            if HAS_FAISS:
                faiss.write_index(self.index, self.vector_db_path)
                with open(self.metadata_path, "w", encoding="utf-8") as f:
                    json.dump(self.metadata, f)
            else:
                self.index.save(self.vector_db_path)
        except Exception as e:
            print(f"Error saving vector index: {e}")

    def load_index(self):
        """Load index and metadata from files if they exist."""
        try:
            if HAS_FAISS:
                if os.path.exists(self.vector_db_path) and os.path.exists(self.metadata_path):
                    self.index = faiss.read_index(self.vector_db_path)
                    with open(self.metadata_path, "r", encoding="utf-8") as f:
                        self.metadata = json.load(f)
            else:
                if os.path.exists(self.vector_db_path):
                    self.index.load(self.vector_db_path)
                    self.metadata = self.index.metadata
        except Exception as e:
            print(f"Error loading vector index: {e}. Starting fresh.")
            # Start fresh on error
            if HAS_FAISS:
                self.index = faiss.IndexFlatIP(self.dimension)
                self.metadata = []
            else:
                self.index = SimpleNumpyIndex(self.dimension)
                self.metadata = []

# Global service instance
rag_service = RAGPipeline()

