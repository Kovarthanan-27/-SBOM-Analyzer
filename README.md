# SBOM Security Analyzer — Risk Ledger 🛡️

An enterprise-grade Software Bill of Materials (SBOM) analyzer that automatically ingests, cross-references, and scores dependency risks using a live LLM remediation engine.

## 🚀 The Problem
Security teams spend countless hours manually tracking dependencies, hunting down transitive vulnerabilities, and cross-referencing legal licenses. When a zero-day drops, the manual audit process is too slow to prevent a breach.

## 💡 Our Solution
The SBOM Risk Ledger automates the entire supply chain audit:
* **Deep Transitive Scanning:** Uncovers hidden vulnerabilities nested deep within safe dependencies.
* **Intelligent Risk Scoring:** Calculates risk using a weighted algorithm based on CVE severity, legal license conflicts (e.g., AGPL), and software decay (abandonware).
* **AI-Powered Remediation:** Integrates with the Groq API (Llama 3.1) to generate real-time, highly specific mitigation strategies for every flagged package.
* **Enterprise Reporting:** One-click generation of beautifully formatted PDF audit reports.

## 📁 Repository Structure
* `/backend`: Python/Flask API engine, SQLite database, and Groq LLM integration.
* `/frontend`: Zero-build Vanilla JS/HTML client with a modern enterprise design system.

## ⚙️ Quick Start
To run this project locally, you will need to start the backend server and open the frontend client. 
1. Follow the setup instructions in `backend/README.md` to start the Flask API.
2. Follow the instructions in `frontend/README.md` to launch the user interface.