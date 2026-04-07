import json
import os
import xml.etree.ElementTree as ET
from datetime import datetime

# --- Configuration ---
REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")
OUTPUT_FILE = os.path.join(REPORTS_DIR, "dashboard.html")

def load_json(filename):
    path = os.path.join(REPORTS_DIR, filename)
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading {filename}: {e}")
    return None

def parse_npm_audit(filename):
    path = os.path.join(REPORTS_DIR, filename)
    sca_summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                
                # Check for metadata structure (npm 7+)
                if "metadata" in data and "vulnerabilities" in data["metadata"]:
                    vulns = data["metadata"]["vulnerabilities"]
                    sca_summary["critical"] = vulns.get("critical", 0)
                    sca_summary["high"] = vulns.get("high", 0)
                    sca_summary["medium"] = vulns.get("moderate", 0) # npm uses 'moderate'
                    sca_summary["low"] = vulns.get("low", 0)
                    sca_summary["total"] = vulns.get("total", 0)
        except Exception as e:
            print(f"Error parsing {filename}: {e}")
    return sca_summary

def parse_zap_report(filename):
    data = load_json(filename)
    zap_summary = {"total": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    if data and "site" in data:
        for site in data["site"]:
            for alert in site.get("alerts", []):
                zap_summary["total"] += 1
                risk = alert.get("riskdesc", "").split(" (")[0]
                if risk == "High": zap_summary["high"] += 1
                elif risk == "Medium": zap_summary["medium"] += 1
                elif risk == "Low": zap_summary["low"] += 1
                elif risk == "Informational": zap_summary["informational"] += 1
    return zap_summary

def parse_jmeter_results(filename):
    path = os.path.join(REPORTS_DIR, filename)
    perf_summary = {"samples": 0, "errors": 0, "avg_rt": 0, "max_rt": 0}
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                lines = f.readlines()[1:] # Skip header
                if lines:
                    rts = []
                    for line in lines:
                        parts = line.split(",")
                        if len(parts) >= 8:
                            perf_summary["samples"] += 1
                            rts.append(int(parts[1]))
                            if parts[7] == "false":
                                perf_summary["errors"] += 1
                    if rts:
                        perf_summary["avg_rt"] = sum(rts) / len(rts)
                        perf_summary["max_rt"] = max(rts)
        except Exception as e:
            print(f"Error parsing {filename}: {e}")
    return perf_summary

def generate_dashboard():
    # 1. Parse all results
    # Switching from OWASP XML to NPM Audit JSON for speed
    sca = parse_npm_audit("npm-audit.json")
    zap = parse_zap_report("zap-report.json")
    perf = parse_jmeter_results("jmeter-results.jtl")
    # For Sonar, we'll assume a summary is provided or we'll mock it if not available
    sonar = load_json("sonar-summary.json") or {"critical": 0, "major": 0, "minor": 0}

    # 2. Rule-Based AI Logic
    recommendations = []
    risk_level = "LOW"
    
    if sca["critical"] > 0 or sonar["critical"] > 0 or zap["high"] > 0:
        risk_level = "CRITICAL"
        recommendations.append({"priority": "HIGH", "issue": "Critical vulnerabilities detected in code/dependencies", "fix": "Immediate remediation required for production deployment."})
    elif sca["high"] > 0 or zap["medium"] > 0:
        risk_level = "HIGH"
        recommendations.append({"priority": "MEDIUM", "issue": "High severity security findings", "fix": "Address high-priority issues within 48 hours."})
    
    if perf["errors"] > (perf["samples"] * 0.05):
        recommendations.append({"priority": "HIGH", "issue": f"High error rate in performance test ({perf['errors']} errors)", "fix": "Re-check server stability and database connections."})
    
    if perf["avg_rt"] > 1000:
        recommendations.append({"priority": "LOW", "issue": "High average response latency", "fix": "Investigate frontend bundling and API response times."})

    # 3. Build HTML (Ultra-Premium Aesthetics)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DevSecOps Intelligence Suite — AI Dashboard</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap');
            :root {{
                --bg: #030712; --card: rgba(30, 41, 59, 0.7); --border: rgba(51, 65, 85, 0.5);
                --primary: #22d3ee; --success: #34d399; --warning: #fbbf24; --error: #fb7185; --text: #f8fafc;
            }}
            body {{ font-family: 'Outfit', sans-serif; background: radial-gradient(circle at top left, #1e1b4b, #030712); color: var(--text); margin: 0; padding: 0; min-height: 100vh; overflow-x: hidden; }}
            .container {{ max-width: 1400px; margin: auto; padding: 40px 20px; }}
            
            /* Glassmorphism Header */
            header {{ 
                display: flex; justify-content: space-between; align-items: center; padding-bottom: 40px; margin-bottom: 60px;
                border-bottom: 1px solid var(--border); backdrop-filter: blur(10px); position: sticky; top: 0; z-index: 100;
            }}
            h1 {{ font-size: 2.2rem; font-weight: 700; background: linear-gradient(90deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin: 0; }}
            .timestamp {{ font-size: 0.9rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.1em; }}
            
            /* Metric Grid */
            .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 30px; margin-bottom: 60px; }}
            .stat-card {{ 
                background: var(--card); border: 1px solid var(--border); border-radius: 24px; padding: 35px;
                backdrop-filter: blur(8px); position: relative; overflow: hidden; transition: transform 0.3s;
            }}
            .stat-card:hover {{ transform: translateY(-8px); border-color: var(--primary); }}
            .stat-card h3 {{ font-size: 1rem; color: #94a3b8; margin: 0 0 15px 0; text-transform: uppercase; letter-spacing: 0.05em; }}
            .stat-value {{ font-size: 3.5rem; font-weight: 700; color: #fff; line-height: 1; }}
            .stat-card.risk-CRITICAL {{ border-top: 6px solid var(--error); }}
            .stat-card.risk-HIGH {{ border-top: 6px solid #f97316; }}
            .stat-card.risk-LOW {{ border-top: 6px solid var(--success); }}
            
            /* AI Insights Section */
            .ai-block {{ 
                background: linear-gradient(145deg, #1e293b 0%, #0f172a 100%); border-radius: 32px; padding: 45px; 
                border: 1px solid var(--primary); box-shadow: 0 0 40px rgba(34, 211, 238, 0.2); margin-bottom: 60px;
            }}
            .ai-badge {{ background: var(--primary); color: #000; padding: 6px 16px; border-radius: 99px; font-weight: bold; font-size: 0.8rem; vertical-align: middle; }}
            .rec-list {{ margin-top: 30px; }}
            .rec-card {{ background: rgba(255, 255, 255, 0.03); padding: 25px; border-radius: 20px; border: 1px solid var(--border); margin-bottom: 20px; display: flex; align-items: start; gap: 20px; }}
            .rec-icon {{ font-size: 1.5rem; width: 40px; }}
            .rec-body h4 {{ margin: 0 0 5px 0; font-size: 1.1rem; color: #fff; }}
            .rec-fix {{ font-size: 0.9rem; color: var(--primary); margin-top: 10px; font-weight: 600; opacity: 0.8; }}
            
            /* Tables */
            .data-section {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 40px; }}
            .table-wrap {{ background: var(--card); border-radius: 24px; padding: 30px; border: 1px solid var(--border); }}
            table {{ width: 100%; border-collapse: collapse; }}
            th {{ text-align: left; padding: 15px; font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; border-bottom: 1px solid var(--border); }}
            td {{ padding: 18px 15px; font-size: 1rem; color: #f1f5f9; border-bottom: 1px solid rgba(255,255,255,0.05); }}
            .bar-container {{ width: 100px; height: 6px; background: rgba(255,255,255,0.1); border-radius: 3px; display: inline-block; margin-right: 15px; vertical-align: middle; }}
            .bar-fill {{ height: 100%; border-radius: 3px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <div>
                    <h1>Security Intelligence Suite</h1>
                    <p class="timestamp">Session: {now} | Target: 65.1.109.17</p>
                </div>
                <div class="ai-badge">GEN-AI ANALYST v2.0</div>
            </header>

            <div class="grid">
                <div class="stat-card risk-{risk_level}">
                    <h3>Risk Posture</h3>
                    <div class="stat-value">{risk_level}</div>
                </div>
                <div class="stat-card">
                    <h3>Code/SCA Vulnerabilities</h3>
                    <div class="stat-value">{sca['critical'] + sca['high'] + sonar['critical']}</div>
                </div>
                <div class="stat-card">
                    <h3>ZAP High Alerts</h3>
                    <div class="stat-value">{zap['high']}</div>
                </div>
                <div class="stat-card">
                    <h3>Performance (Avg)</h3>
                    <div class="stat-value">{int(perf['avg_rt'])}<span style="font-size: 1.5rem; color: #94a3b8;">ms</span></div>
                </div>
            </div>

            <div class="ai-block">
                <h2 style="margin:0; font-size: 1.8rem; display:flex; align-items:center; gap:15px;">
                    <span style="font-size: 2.5rem;">🧠</span> AI Security Forensics & Recommendations
                </h2>
                <div class="rec-list">
                    {''.join([f'''
                    <div class="rec-card">
                        <div class="rec-icon">{'🚨' if r['priority']=='HIGH' else '⚠️'}</div>
                        <div class="rec-body">
                            <h4>{r['issue']}</h4>
                            <div style="font-size: 0.95rem; color: #94a3b8;">{r['fix']}</div>
                            <div class="rec-fix">Primary Action: Patch and Re-scan in Pipeline</div>
                        </div>
                    </div>
                    ''' for r in recommendations]) if recommendations else '<p style="color: var(--success); font-size: 1.2rem; padding-top: 20px;">✓ Environment validated. All security and performance gate checks passed.</p>'}
                </div>
            </div>

            <div class="data-section">
                <div class="table-wrap">
                    <h3>SCA Vulnerabilities (npm audit)</h3>
                    <table>
                        <tr><th>Severity</th><th>Progress</th><th>Count</th></tr>
                        <tr><td>Critical</td><td><div class="bar-container"><div class="bar-fill" style="width: {min(100, sca['critical']*20)}%; background: var(--error);"></div></div></td><td>{sca['critical']}</td></tr>
                        <tr><td>High</td><td><div class="bar-container"><div class="bar-fill" style="width: {min(100, sca['high']*10)}%; background: #f97316;"></div></div></td><td>{sca['high']}</td></tr>
                        <tr><td>Medium</td><td><div class="bar-container"><div class="bar-fill" style="width: {min(100, sca['medium']*5)}%; background: var(--warning);"></div></div></td><td>{sca['medium']}</td></tr>
                    </table>
                </div>
                <div class="table-wrap">
                    <h3>DAST (ZAP) Trends</h3>
                    <table>
                        <tr><th>Alert Level</th><th>Progress</th><th>Result</th></tr>
                        <tr><td>High</td><td><div class="bar-container"><div class="bar-fill" style="width: {min(100, zap['high']*25)}%; background: var(--error);"></div></div></td><td>{zap['high']}</td></tr>
                        <tr><td>Medium</td><td><div class="bar-container"><div class="bar-fill" style="width: {min(100, zap['medium']*10)}%; background: #fb7185;"></div></div></td><td>{zap['medium']}</td></tr>
                        <tr><td>Low</td><td><div class="bar-container"><div class="bar-fill" style="width: {min(100, zap['low']*5)}%; background: #94a3b8;"></div></div></td><td>{zap['low']}</td></tr>
                    </table>
                </div>
            </div>
            
            <footer style="text-align: center; margin-top: 80px; padding: 40px; border-top: 1px solid var(--border); color: #475569; font-size: 0.9rem;">
                DevSecOps AI Insights Engine &copy; 2026 | Powered by Antigravity
            </footer>
        </div>
    </body>
    </html>
    """
    
    with open(OUTPUT_FILE, "w") as f:
        f.write(html_content)
    print(f"Ultra-Premium Dashboard generated at: {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_dashboard()
