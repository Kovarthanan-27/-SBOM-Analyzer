import sqlite3
import os

DB_PATH = 'sbom_database.db'

def init_db():
    # Remove existing db for clean slate during hackathon testing
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Table 1: Applications
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS application (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            owner TEXT,
            criticality TEXT
        )
    ''')

    # Table 2: Dependencies (The SBOM contents)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dependency (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id INTEGER,
            name TEXT NOT NULL,
            version TEXT,
            license TEXT,
            is_transitive BOOLEAN,
            last_updated TEXT,
            FOREIGN KEY (app_id) REFERENCES application (id)
        )
    ''')

    # Table 3: Vulnerabilities (The mapped CVEs)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dependency_id INTEGER,
            cve_id TEXT NOT NULL,
            severity TEXT,
            cvss_score REAL,
            FOREIGN KEY (dependency_id) REFERENCES dependency (id)
        )
    ''')

    conn.commit()
    conn.close()
    print("Database and schema initialized successfully.")

if __name__ == '__main__':
    init_db()