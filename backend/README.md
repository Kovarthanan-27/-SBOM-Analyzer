# Backend — SBOM Security Analyzer ⚙️

The core engine powering the SBOM Risk Ledger. Built for speed and simplicity, this Flask application handles data ingestion, SQLite database management, and coordinates the Groq API calls to generate real-time vulnerability remediation playbooks.

## 🛠️ Tech Stack
* **Framework:** Python / Flask
* **Database:** SQLite
* **AI Engine:** Groq API (Prompt-engineered for precise, one-sentence playbooks)

## 📦 Setup Instructions

1. **Navigate to the backend directory:**
   ```bash
   cd backend
   ```

2. **Set up a virtual environment (Recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure your API Key:**
   An `.env` file template has already been provided in the root of the `backend` directory.
   * Open the `.env` file with any text editor.
   * Replace the placeholder text with your actual Groq API key:
     ```
     GROQ_API_KEY=your_actual_api_key_here
     ```
   * Save and close the file. (Note: Ensure this file is never committed to a public GitHub repository).

5. **Initialize and Run the Server:**
   The database schema will automatically initialize on the first run.
   ```bash
   python app.py
   ```

The API will now be active at `http://localhost:5000`.