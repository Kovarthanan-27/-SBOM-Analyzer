from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3

app = Flask(__name__)
# Enable CORS to allow the frontend to communicate with this backend
CORS(app)

DB_PATH = 'sbom_database.db'

def get_db_connection():
    """Helper function to open a SQLite connection and return rows as dictionaries."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/', methods=['GET'])
def home():
    """Root endpoint so the browser doesn't show a 404."""
    return jsonify({
        "status": "online", 
        "project": "SBOM Analyzer",
        "message": "API is running. Frontend should connect to /api/ endpoints."
    }), 200
    
@app.route('/api/health', methods=['GET'])
def health_check():
    """Simple endpoint to verify the server is running."""
    return jsonify({"status": "healthy", "message": "SBOM Analyzer Engine is running."}), 200

# The data ingestion endpoint (Prompt 2 will fill this in)
@app.route('/api/upload', methods=['POST'])
def upload_files():
    return jsonify({"message": "Endpoint ready for data ingestion logic."}), 501

# The scoring and results endpoint (Prompt 3 & 4 will fill this in)
@app.route('/api/scan-results', methods=['GET'])
def get_scan_results():
    return jsonify({"message": "Endpoint ready for scoring and LLM integration."}), 501

if __name__ == '__main__':
    # Running on port 5000 with debug mode enabled for rapid iteration
    app.run(debug=True, port=5000)