from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import csv
import json
import io
# ... (keep your existing imports and setup) ...

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
    # 1. Verify files are in the request
    if 'sbom_file' not in request.files or 'vuln_file' not in request.files:
        return jsonify({"error": "Missing files. Please upload both sbom_file and vuln_file."}), 400

    sbom_file = request.files['sbom_file']
    vuln_file = request.files['vuln_file']

    try:
        # 2. Parse the Vulnerability JSON into a fast-lookup dictionary
        vuln_data = json.load(vuln_file)
        vuln_lookup = {}
        for v in vuln_data:
            pkg_name = v.get('package', '').lower()
            if pkg_name not in vuln_lookup:
                vuln_lookup[pkg_name] = []
            vuln_lookup[pkg_name].append(v)

        # 3. Read the CSV file in memory
        stream = io.StringIO(sbom_file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.DictReader(stream)

        conn = get_db_connection()
        cursor = conn.cursor()
        
        apps_cache = {} # Keeps track of inserted apps so we don't duplicate them

        # 4. Loop through the SBOM and insert records
        for row in csv_reader:
            app_name = row.get('app_name', 'Unknown App')
            lib_name = row.get('library_name', '').lower()
            
            # Insert Application (if we haven't seen it yet)
            if app_name not in apps_cache:
                cursor.execute("INSERT INTO application (name, owner, criticality) VALUES (?, ?, ?)", 
                               (app_name, "Admin", "High"))
                apps_cache[app_name] = cursor.lastrowid
            
            app_id = apps_cache[app_name]

            # Insert Dependency
            cursor.execute("""
                INSERT INTO dependency (app_id, name, version, license, is_transitive, last_updated)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                app_id, 
                row.get('library_name'), 
                row.get('version'), 
                row.get('license'), 
                str(row.get('is_transitive')).lower() == 'true',
                row.get('last_updated')
            ))
            dep_id = cursor.lastrowid

            # Cross-reference and Insert Vulnerabilities
            if lib_name in vuln_lookup:
                for vuln in vuln_lookup[lib_name]:
                    cursor.execute("""
                        INSERT INTO vulnerability (dependency_id, cve_id, severity, cvss_score)
                        VALUES (?, ?, ?, ?)
                    """, (
                        dep_id,
                        vuln.get('cve_id'),
                        vuln.get('severity'),
                        float(vuln.get('cvss', 0.0))
                    ))

        conn.commit()
        conn.close()

        return jsonify({
            "message": "Data ingested and cross-referenced successfully!", 
            "applications_processed": len(apps_cache)
        }), 200

    except Exception as e:
        return jsonify({"error": f"Failed to process files: {str(e)}"}), 500


# The scoring and results endpoint (Prompt 3 & 4 will fill this in)
@app.route('/api/scan-results', methods=['GET'])
def get_scan_results():
    return jsonify({"message": "Endpoint ready for scoring and LLM integration."}), 501

if __name__ == '__main__':
    # Running on port 5000 with debug mode enabled for rapid iteration
    app.run(debug=True, port=5000)