from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import csv
import json
import io
import os
import requests
from dotenv import load_dotenv

# Load the .env file immediately
load_dotenv()
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

from datetime import datetime

import os
import requests

def get_ai_remediation(dependency_name, cve_count, cve_list):
    """Calls the Groq Mixtral LLM to generate a specific fix for flagged dependencies."""
    if cve_count == 0:
        return "No known CVEs — no action required."

    primary_cve = cve_list[0] if cve_list else "Unknown CVE"
    
    # Strict prompt engineering to force a single, actionable sentence
    prompt = f"You are a cybersecurity expert. The software package '{dependency_name}' has the vulnerability '{primary_cve}'. Provide exactly one concise, actionable sentence explaining how a developer should fix or mitigate this."

    api_key = os.getenv("GROQ_API_KEY")
    
    # Safety net: If the API key isn't found, fall back gracefully instead of crashing
    if not api_key:
        print("Warning: GROQ_API_KEY not found. Using fallback text.")
        return f"AI Suggestion: Upgrade '{dependency_name}' to patch the {primary_cve} vulnerability immediately."

    url = "https://api.groq.com/openai/v1/chat/completions" 
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "llama-3.1-8b-instant", 
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2, 
        "max_tokens": 60    
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=5)
        
        # NEW: If it fails, print the exact reason Groq gives us before throwing the error
        if response.status_code != 200:
            print(f"Groq Rejection Details: {response.text}")
            
        response.raise_for_status() 
        
        ai_text = response.json()['choices'][0]['message']['content'].strip(' "\'')
        return ai_text
        
    except requests.exceptions.RequestException as e:
        print(f"AI API Error: {e}")
        return f"Patch '{dependency_name}' to resolve {primary_cve}."

        
def calculate_application_scores():
    """
    Computes the composite risk score for each application based on the formula:
    Score = Sum of [ (CVE count * severity_weight) + license_penalty + maintenance_penalty ]
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Fetch all applications
    cursor.execute("SELECT id, name FROM application")
    applications = cursor.fetchall()
    
    app_scores = {}
    current_year = 2026  # Anchored to project timeline

    # Define weight metrics
    severity_weights = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2
    }

    for app in applications:
        app_id = app['id']
        app_name = app['name']
        
        # 2. Fetch all dependencies belonging to this specific application
        cursor.execute("SELECT id, name, license, last_updated FROM dependency WHERE app_id = ?", (app_id,))
        dependencies = cursor.fetchall()
        
        total_score = 0
        dependency_reports = []

        for dep in dependencies:
            dep_id = dep['id']
            dep_name = dep['name']
            dep_license = dep['license'] or ""
            last_updated_str = dep['last_updated'] or ""
            
            # Fetch severity AND cve_id this time
            cursor.execute("SELECT cve_id, severity FROM vulnerability WHERE dependency_id = ?", (dep_id,))
            vulns = cursor.fetchall()
            
            cve_count = len(vulns)
            vuln_score = 0
            cve_list = []
            
            for v in vulns:
                severity = v['severity'].lower()
                vuln_score += severity_weights.get(severity, 2)
                cve_list.append(v['cve_id']) # Save the CVEs for the AI
            
            base_vuln_component = vuln_score 
            
            license_penalty = 0
            if "gpl" in dep_license.lower():
                license_penalty = 5
                
            maintenance_penalty = 0
            if last_updated_str:
                try:
                    year = int(last_updated_str.split('-')[0])
                    if (current_year - year) > 2:
                        maintenance_penalty = 5
                except ValueError:
                    pass
            
            dep_composite_score = base_vuln_component + license_penalty + maintenance_penalty
            total_score += dep_composite_score
            
            # --- CALL THE AI REMEDIATION ENGINE ---
            remediation_advice = get_ai_remediation(dep_name, cve_count, cve_list)
            
            dependency_reports.append({
                "dependency_name": dep_name,
                "cve_count": cve_count,
                "cve_list": cve_list, # Handing this to the UI
                "license": dep_license,
                "last_updated": last_updated_str,
                "score_contribution": dep_composite_score,
                "ai_remediation": remediation_advice # The Wow Factor!
            })

        app_scores[app_name] = {
            "application_id": app_id,
            "total_risk_score": total_score,
            "breakdown": dependency_reports
        }

    conn.close()
    return app_scores

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
    try:
        # Calculate scores dynamically across all ingested records
        scores = calculate_application_scores()
        return jsonify({
            "status": "success",
            "computed_at": datetime.now().isoformat(),
            "results": scores
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to compute risk assessment: {str(e)}"}), 500
if __name__ == '__main__':
    # Running on port 5000 with debug mode enabled for rapid iteration
    app.run(debug=True, port=5000)