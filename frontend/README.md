# Frontend — SBOM Security Analyzer 🎨

A lightweight, zero-build client designed to visualize the risk ledger securely and efficiently. Built with Vanilla JavaScript and HTML to ensure rapid rendering and easy deployment without the overhead of heavy frameworks.

## 🛠️ Architecture
* **Markup & Styling:** HTML5 and Custom CSS (Enterprise Design System)
* **Logic:** Vanilla JavaScript (ES6+)
* **Integration:** REST API polling via Fetch API to the Flask backend.

## 🚀 How to Run

Because this is a zero-build vanilla client, you do not need Node.js or npm to run the application locally.

1. **Start the Backend First:**
   Ensure your Flask backend is running so the frontend can successfully ping the `/api/upload` and `/api/scan-results` endpoints.

2. **Serve the UI:**
   You can open `index.html` directly in your browser. However, to prevent any strict CORS policies from blocking local file execution, it is recommended to serve the directory using a simple local server.

   If you have Python installed, simply run this inside the `frontend` folder:
   ```bash
   python -m http.server 8000
   ```

3. **Access the Dashboard:**
   Open your browser and navigate to `http://localhost:8000`.

4. **Testing the Scan:**
   Use the sample SBOM (`.csv`) and Vulnerability (`.json`) files provided in the repository to trigger a scan, view the dynamic UI, and see the AI-generated remediation playbooks in action.
