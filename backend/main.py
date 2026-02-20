import os
import subprocess
import json
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from typing import List, Dict
from reportlab.lib.pagesizes import letter
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
import re
from typing import List, Dict

app = FastAPI(title="PCAP Forensics API")

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
# Use 'tshark' from PATH by default for Linux/Docker, fallback to Windows path
TSHARK_PATH = os.getenv("TSHARK_PATH", "tshark" if os.name != "nt" else r"C:\Program Files\Wireshark\tshark.exe")

os.makedirs(UPLOAD_DIR, exist_ok=True)

def parse_phs(phs_output: str) -> List[Dict]:
    """Parses tshark -z io,phs output into a list of dictionaries for charting."""
    data = []
    lines = phs_output.split('\n')
    for line in lines:
        match = re.search(r'(\w+)\s+frames:(\d+)\s+bytes:(\d+)', line)
        if match:
            data.append({
                "protocol": match.group(1),
                "frames": int(match.group(2)),
                "bytes": int(match.group(3))
            })
    return data[:8]  # Limit to top 8 for UI

def parse_conv(conv_output: str) -> List[Dict]:
    """Parses tshark -z conv,ip output into structured host conversation data."""
    data = []
    lines = conv_output.split('\n')
    # Skip headers and footers, look for IP <-> IP pattern
    for line in lines:
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)', line)
        if match:
            data.append({
                "src": match.group(1),
                "dst": match.group(2),
                "packets": int(match.group(3)),
                "bytes": int(match.group(4)),
                "total_packets": int(match.group(5)),
                "total_bytes": int(match.group(6))
            })
    return sorted(data, key=lambda x: x['total_bytes'], reverse=True)[:10]

def calculate_risk(expert_info: str, proto_stats: str) -> Dict:
    """Calculates a heuristic risk score (0-100)."""
    score = 0
    reasons = []
    
    # Expert info reveals errors/warnings
    if "Error" in expert_info:
        score += 40
        reasons.append("Critical expert errors detected in traffic.")
    if "Warning" in expert_info:
        score += 20
        reasons.append("Anomalous expert warnings identified.")
        
    # Protocol anomalies
    if "dns" in proto_stats.lower() and "http" not in proto_stats.lower():
        score += 15
        reasons.append("DNS-only traffic detected (possible exfiltration).")
    
    if "irc" in proto_stats.lower() or "telnet" in proto_stats.lower():
        score += 25
        reasons.append("Legacy/Insecure protocols detected (IRC/Telnet).")
        
    return {
        "score": min(score, 100),
        "level": "High" if score > 60 else "Medium" if score > 30 else "Low",
        "reasons": reasons
    }

@app.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Invalid file type. Only PCAP/PCAPNG allowed.")
    
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    try:
        # 1. Get Protocol Stats
        proto_stats = subprocess.check_output([
            TSHARK_PATH, "-r", file_path, "-z", "io,phs"
        ]).decode()

        # 2. Get Expert Info
        expert_info = subprocess.check_output([
            TSHARK_PATH, "-r", file_path, "-z", "expert"
        ]).decode()

        # 3. Get Conversations
        conv_stats = subprocess.check_output([
            TSHARK_PATH, "-r", file_path, "-z", "conv,ip"
        ]).decode()

        risk_analysis = calculate_risk(expert_info, proto_stats)
        parsed_protocols = parse_phs(proto_stats)
        parsed_hosts = parse_conv(conv_stats)

        return {
            "filename": file.filename,
            "filepath": file_path,
            "protocol_hierarchy": proto_stats,
            "protocols_chart": parsed_protocols,
            "top_talkers": parsed_hosts,
            "expert_info": expert_info,
            "risk": risk_analysis,
            "status": "success"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/generate_report")
async def generate_report(data: Dict):
    filename = data.get("filename")
    report_path = os.path.join(UPLOAD_DIR, f"{filename}_report.pdf")
    
    doc = SimpleDocTemplate(report_path, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom Title Style
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.HexColor("#3b82f6")
    )
    
    story = []
    story.append(Paragraph(f"Forensics Report: {filename}", title_style))
    story.append(Spacer(1, 12))
    
    story.append(Paragraph("Protocol Hierarchy Statistics", styles['Heading2']))
    story.append(Paragraph(data.get("protocol_hierarchy", "").replace("\n", "<br/>"), styles['Code']))
    story.append(Spacer(1, 12))
    
    story.append(Paragraph("Expert Info Details", styles['Heading2']))
    story.append(Paragraph(data.get("expert_info", "").replace("\n", "<br/>"), styles['Code']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Host Communication Analysis (Top Talkers)", styles['Heading2']))
    hosts = data.get("top_talkers", [])
    if hosts:
        table_data = [["Source", "Destination", "Bytes", "Packets"]]
        for h in hosts:
            table_data.append([h['src'], h['dst'], f"{h['total_bytes']} B", h['total_packets']])
        
        t = Table(table_data, colWidths=[150, 150, 80, 80])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#3b82f6")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No host conversation data available.", styles['Normal']))
    
    doc.build(story)
    
    return FileResponse(report_path, filename=f"Forensics_Report_{filename}.pdf")

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
