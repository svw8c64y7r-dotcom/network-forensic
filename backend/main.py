import os
import subprocess
import re
import shutil
import html
import io
from typing import List, Dict
from fastapi import FastAPI, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = FastAPI(title="PacketPrism API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"]
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
async def analyze_pcap(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
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

        # Generate PDF report immediately
        report_data = {
            "filename": file.filename,
            "risk": risk_analysis,
            "protocol_hierarchy": proto_stats,
            "top_talkers": parsed_hosts
        }
        report_filename = f"report_{file.filename}.pdf"
        report_path = os.path.join(UPLOAD_DIR, report_filename)
        generate_pdf_file(report_data, report_path)

        # Cleanup: Remove files older than 30 minutes to save space
        background_tasks.add_task(cleanup_old_files)

        return {
            "filename": file.filename,
            "filepath": file_path,
            "protocol_hierarchy": proto_stats,
            "protocols_chart": parsed_protocols,
            "top_talkers": parsed_hosts,
            "expert_info": expert_info,
            "risk": risk_analysis,
            "report_url": f"/download/{report_filename}",
            "status": "success"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def generate_pdf_file(data: Dict, output_path: str):
    """Helper to generate a PDF file from analysis data."""
    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        
        if 'PrismCode' not in styles:
            styles.add(ParagraphStyle(
                name='PrismCode', 
                fontName='Courier', 
                fontSize=8, 
                leading=10,
                wordWrap='CJK'
            ))
        
        story = []
        story.append(Paragraph("PacketPrism Forensics Report", styles['Title']))
        story.append(Paragraph(f"File: {html.escape(str(data.get('filename', 'Unknown')))}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        risk = data.get("risk", {})
        story.append(Paragraph(f"Risk Assessment: {html.escape(str(risk.get('level', 'N/A')))} (Score: {risk.get('score', 0)})", styles['Heading2']))
        reasons = risk.get("reasons", [])
        if reasons:
            for reason in reasons:
                story.append(Paragraph(f"• {html.escape(str(reason))}", styles['Normal']))
        else:
            story.append(Paragraph("No anomalies detected.", styles['Normal']))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Protocol Hierarchy", styles['Heading2']))
        hierarchy_text = data.get("protocol_hierarchy", "No hierarchy data available.")
        story.append(Preformatted(hierarchy_text, styles['PrismCode']))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("Host Communication Analysis (Top Talkers)", styles['Heading2']))
        hosts = data.get("top_talkers", [])
        if hosts and isinstance(hosts, list):
            table_data = [["Source", "Destination", "Bytes", "Packets"]]
            for h in hosts:
                table_data.append([
                    html.escape(str(h.get('src', 'N/A'))), 
                    html.escape(str(h.get('dst', 'N/A'))), 
                    f"{h.get('total_bytes', 0)} B", 
                    str(h.get('total_packets', 0))
                ])
            
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
        with open(output_path, "wb") as f:
            f.write(buffer.getvalue())
        buffer.close()
    except Exception as e:
        print(f"Internal PDF Generation Error: {str(e)}")
        raise e

def cleanup_old_files():
    """Removes files from UPLOAD_DIR that are older than 30 minutes."""
    import time
    now = time.time()
    for f in os.listdir(UPLOAD_DIR):
        f_path = os.path.join(UPLOAD_DIR, f)
        # 1800 seconds = 30 minutes
        if os.path.isfile(f_path) and os.stat(f_path).st_mtime < now - 1800:
            try:
                os.remove(f_path)
            except:
                pass

@app.get("/download/{filename}")
async def download_file(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        file_path,
        media_type='application/pdf',
        filename=filename
    )

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
