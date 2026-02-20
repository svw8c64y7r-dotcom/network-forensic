import os
import subprocess
import re
import shutil
from typing import List, Dict
from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = FastAPI(title="AetherTrace API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
TSHARK_PATH = os.getenv("TSHARK_PATH", "tshark" if os.name != "nt" else r"C:\Program Files\Wireshark\tshark.exe")

os.makedirs(UPLOAD_DIR, exist_ok=True)

def parse_phs(phs_output: str) -> List[Dict]:
    """Parses tshark -z io,phs output into structured protocol data."""
    data = []
    lines = phs_output.split('\n')
    for line in lines:
        match = re.search(r'(\w+)\s+frames:(\d+)\s+bytes:(\d+)', line)
        if match:
            data.append({
                "protocol": match.group(1),
                "packets": int(match.group(2)),
                "bytes": int(match.group(3))
            })
    return data[:8]  # Limit to top 8 for UI

def parse_conv(conv_output: str) -> List[Dict]:
    """Parses tshark -z conv,ip output into structured host conversation data."""
    data = []
    lines = conv_output.split('\n')
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
    
    if "Error" in expert_info:
        score += 40
        reasons.append("Critical Expert Errors detected (Potential Malformed Packets/Attacks)")
    elif "Warn" in expert_info:
        score += 20
        reasons.append("Expert Warnings found in traffic stream")
        
    if "Telnet" in proto_stats or "IRC" in proto_stats:
        score += 30
        reasons.append("Insecure/Legacy protocols detected (Telnet/IRC)")
        
    if "DNS" in proto_stats and len(proto_stats.split('\n')) < 5:
        score += 15
        reasons.append("Anomalous DNS-only traffic pattern (Potential C2/Exfiltration)")

    level = "Low"
    if score >= 70: level = "High"
    elif score >= 30: level = "Medium"
    
    return {"score": min(score, 100), "level": level, "reasons": reasons if reasons else ["No major anomalies detected."]}

@app.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
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
        return {"status": "error", "message": str(e)}

@app.post("/generate_report")
async def generate_report(data: Dict):
    report_filename = f"report_{data.get('filename', 'analysis')}.pdf"
    report_path = os.path.join(UPLOAD_DIR, report_filename)
    
    doc = SimpleDocTemplate(report_path, pagesize=letter)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Code', fontName='Courier', fontSize=8, leading=10))
    story = []

    story.append(Paragraph("AetherTrace Forensics Report", styles['Title']))
    story.append(Paragraph(f"File: {data.get('filename')}", styles['Normal']))
    story.append(Spacer(1, 12))
    
    risk = data.get("risk", {})
    story.append(Paragraph(f"Risk Assessment: {risk.get('level', 'N/A')} (Score: {risk.get('score', 0)})", styles['Heading2']))
    for reason in risk.get("reasons", []):
        story.append(Paragraph(f"• {reason}", styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Protocol Hierarchy", styles['Heading2']))
    story.append(Paragraph(data.get("protocol_hierarchy", "").replace("\n", "<br/>"), styles['Code']))
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
    
    doc.build(story)
    return FileResponse(report_path, filename=report_filename, media_type='application/pdf')

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
