# 💰 RiskLens ProLite: Quantifying Cyber Risk in Financial Terms (FAIR Engine)

## ⭐ Project Summary: Bridging Security and Business
RiskLens ProLite is a cutting-edge security analysis tool designed to solve a critical business problem: transforming technical vulnerabilities into monetary loss projections.

It moves security analysis beyond simple incident counting:  
- ❌ "We had 892 incidents"  
- ✅ "The expected annual loss is $289 Million"  

This allows executives to make **data-driven decisions** on security budgeting, resource allocation, and mitigation prioritization.

---

## 💡 The Core Idea: Why Quantitative Risk (FAIR)?
Our project uses the globally adopted **FAIR (Factor Analysis of Information Risk)** framework and **Monte Carlo Simulation** to establish a financially-based risk language.

| Traditional Method (Qualitative) | RiskLens ProLite (Quantitative - FAIR) |
|---------------------------------|----------------------------------------|
| ❌ "High Risk"                   | ✅ $289,758,275 Expected Annual Loss (ALE) |
| ❌ Focus on Vulnerabilities      | ✅ Focus on Financial Impact and Loss Exposure |
| ❌ Based on Gut Feeling           | ✅ Based on Probabilistic Modeling (Monte Carlo) |

This methodology is highly valuable in professional settings, enabling clear communication of risk in monetary terms.

---

## 🛠️ Key Features and Architecture
The project is built around a **modular pipeline** for efficiency and scalability:

- **Log Ingestion (`log_reader.py`)**: Reads and parses raw security logs (Windows EVTX, Syslog).  
- **Incident Detection (`analyzer.py`)**: Uses configurable rules (`config.json`) to identify security incidents (e.g., Failed Logins, Suspicious Processes).  
- **FAIR Risk Engine (`fair_engine.py`)**: Processes incident frequency and loss magnitude using 10,000+ Monte Carlo simulations to calculate **Annualized Loss Exposure (ALE)**.  
- **Executive Reporting (`exporter.py`)**: Generates professional PDF reports (ready for C-level) and exports raw data (CSV/JSON).  

---

## 📊 Sample Impact

| Incident Type          | Detected Count | Annual Loss Exposure (ALE) | Max Loss Projection |
|------------------------|---------------|----------------------------|-------------------|
| Privilege Escalation   | 827           | $289,758,275              | $507,480,166      |
| Failed Login Attempts  | 65            | $457,652                   | $810,064          |

**Conclusion:** Mitigation efforts should focus on **Privilege Escalation**, as it carries the highest financial risk.

---

## 🚀 Future Enhancements
- **Live Connectors**: API connectors for Splunk, Sentinel, Elastic for real-time data fetching.  
- **Behavioral Analysis**: Integrating behavioral detection to find Zero-Day threats.

---

## 💻 Getting Started

### Installation
Requires **Python 3.8+**. Install dependencies:

```bash
pip install -r requirements.txt
Execution
bash
Copy code
python main.py --config config.json --windows-log-file path/to/logs.evtx
🤝 Contribution
We welcome contributions!
Please open an issue or submit a Pull Request to refine the FAIR model parameters or enhance log analysis.

© 2025 | RiskLens ProLite Project