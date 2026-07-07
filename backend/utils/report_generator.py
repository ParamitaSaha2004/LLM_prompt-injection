import os
import csv
from io import BytesIO
from database import get_db_connection

# Fallback imports
try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

class ReportGenerator:
    @staticmethod
    def generate_excel_report():
        """Generates an Excel workbook containing attack logs, system metrics, and document stats."""
        buffer = BytesIO()
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # 1. Fetch attack logs
                cursor.execute(
                    """SELECT l.id, u.username, l.timestamp, l.attack_type, l.risk_score, l.severity, l.decision, l.explanation 
                       FROM attack_logs l LEFT JOIN users u ON l.user_id = u.id 
                       ORDER BY l.timestamp DESC"""
                )
                logs = cursor.fetchall()
                
                # 2. Fetch general stats
                cursor.execute("SELECT COUNT(*) as total_users FROM users")
                users_count = cursor.fetchone()['total_users']
                
                cursor.execute("SELECT COUNT(*) as total_docs FROM documents")
                docs_count = cursor.fetchone()['total_docs']
                
                cursor.execute("SELECT COUNT(*) as total_attempts FROM attack_logs")
                attempts_count = cursor.fetchone()['total_attempts']
                
                cursor.execute("SELECT AVG(risk_score) as avg_risk FROM attack_logs")
                avg_risk = cursor.fetchone()['avg_risk'] or 0.0

            if HAS_PANDAS:
                # Create pandas dataframes
                df_logs = pd.DataFrame(logs) if logs else pd.DataFrame(columns=['id', 'username', 'timestamp', 'attack_type', 'risk_score', 'severity', 'decision', 'explanation'])
                
                df_stats = pd.DataFrame([{
                    "Metric": "Total Registered Users", "Value": users_count
                }, {
                    "Metric": "Uploaded Documents", "Value": docs_count
                }, {
                    "Metric": "Prompt Injection Attempts", "Value": attempts_count
                }, {
                    "Metric": "Average Risk Score", "Value": round(float(avg_risk), 2)
                }])

                # Write to Excel using pandas ExcelWriter
                with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
                    df_stats.to_excel(writer, sheet_name='Summary', index=False)
                    df_logs.to_excel(writer, sheet_name='Attack Logs', index=False)
                
                buffer.seek(0)
                return buffer.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "PromptShield_Security_Report.xlsx"
            else:
                # If pandas is missing, return a CSV of attack logs
                csv_buffer = BytesIO()
                writer = csv.writer(csv_buffer)
                writer.writerow(['ID', 'Username', 'Timestamp', 'Attack Type', 'Risk Score', 'Severity', 'Decision', 'Explanation'])
                for log in logs:
                    writer.writerow([log['id'], log['username'], log['timestamp'], log['attack_type'], log['risk_score'], log['severity'], log['decision'], log['explanation']])
                
                csv_buffer.seek(0)
                return csv_buffer.getvalue(), "text/csv", "PromptShield_Security_Report.csv"

        except Exception as e:
            print(f"Error generating Excel report: {e}")
            return b"", "text/plain", "error.txt"
        finally:
            conn.close()

    @staticmethod
    def generate_pdf_report():
        """Generates a structured PDF security report with graphs/charts summarized in tables."""
        buffer = BytesIO()
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # Fetch statistics
                cursor.execute("SELECT COUNT(*) as total_users FROM users")
                users_count = cursor.fetchone()['total_users']
                cursor.execute("SELECT COUNT(*) as total_docs FROM documents")
                docs_count = cursor.fetchone()['total_docs']
                cursor.execute("SELECT COUNT(*) as total_attempts FROM attack_logs")
                attempts_count = cursor.fetchone()['total_attempts']
                cursor.execute("SELECT AVG(risk_score) as avg_risk FROM attack_logs")
                avg_risk = cursor.fetchone()['avg_risk'] or 0.0
                cursor.execute("SELECT COUNT(*) as blocked_count FROM attack_logs WHERE decision = 'Blocked'")
                blocked_count = cursor.fetchone()['blocked_count']

                # Fetch recent attack logs (up to 15)
                cursor.execute(
                    """SELECT l.timestamp, l.attack_type, l.risk_score, l.severity, l.decision 
                       FROM attack_logs l ORDER BY l.timestamp DESC LIMIT 15"""
                )
                recent_logs = cursor.fetchall()
        except Exception as e:
            print(f"Database error in PDF export: {e}")
            return b"", "text/plain", "error.txt"
        finally:
            conn.close()

        if HAS_REPORTLAB:
            try:
                doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
                story = []
                styles = getSampleStyleSheet()
                
                # Styles
                title_style = ParagraphStyle(
                    'ReportTitle',
                    parent=styles['Heading1'],
                    fontSize=22,
                    textColor=colors.HexColor('#0F172A'), # dark slate
                    spaceAfter=15
                )
                subtitle_style = ParagraphStyle(
                    'ReportSubtitle',
                    parent=styles['Normal'],
                    fontSize=10,
                    textColor=colors.HexColor('#64748B'),
                    spaceAfter=25
                )
                heading_style = ParagraphStyle(
                    'SectionHeading',
                    parent=styles['Heading2'],
                    fontSize=14,
                    textColor=colors.HexColor('#1E293B'),
                    spaceBefore=15,
                    spaceAfter=10
                )
                body_style = ParagraphStyle(
                    'BodyText',
                    parent=styles['Normal'],
                    fontSize=10,
                    textColor=colors.HexColor('#334155'),
                    spaceAfter=10
                )

                # Header
                story.append(Paragraph("PROMPTSHIELD SECURITY AUDIT REPORT", title_style))
                story.append(Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Target: RAG LLM Security", subtitle_style))
                story.append(Spacer(1, 10))

                # Overview
                story.append(Paragraph("1. Executive Summary", heading_style))
                story.append(Paragraph(
                    "PromptShield actively monitors, detects, and mitigates Prompt Injection Attacks (both direct user injection and indirect document-context poisoning) in the Retrieval-Augmented Generation (RAG) lifecycle. This audit report summarizes system-wide metrics and detected injection attempts.",
                    body_style
                ))
                story.append(Spacer(1, 10))

                # Stats Table
                story.append(Paragraph("2. Safety Metrics Summary", heading_style))
                stats_data = [
                    ['Security Metric', 'Value'],
                    ['Total Registered Users', str(users_count)],
                    ['Uploaded & Indexed Documents', str(docs_count)],
                    ['Prompt Injection Attacks Detected', str(attempts_count)],
                    ['Blocked Injection Attempts', str(blocked_count)],
                    ['Average Attack Risk Score', f"{round(float(avg_risk), 1)} / 100"]
                ]
                stats_table = Table(stats_data, colWidths=[250, 150])
                stats_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                    ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                    ('TOPPADDING', (0,0), (-1,-1), 8),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#F8FAFC'), colors.white]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                ]))
                story.append(stats_table)
                story.append(Spacer(1, 20))

                # Logs Table
                story.append(Paragraph("3. Recent Attack Incidents Log", heading_style))
                if not recent_logs:
                    story.append(Paragraph("No security incidents or attack attempts recorded in database.", body_style))
                else:
                    log_headers = ['Timestamp', 'Attack Category', 'Risk', 'Severity', 'Decision']
                    log_data = [log_headers]
                    for item in recent_logs:
                        log_data.append([
                            str(item['timestamp'])[:16],
                            item['attack_type'],
                            f"{item['risk_score']}/100",
                            item['severity'],
                            item['decision']
                        ])
                    
                    log_table = Table(log_data, colWidths=[120, 150, 60, 80, 80])
                    log_table.setStyle(TableStyle([
                        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#64748B')),
                        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                        ('TOPPADDING', (0,0), (-1,-1), 6),
                        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#F8FAFC'), colors.white]),
                        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
                    ]))
                    story.append(log_table)

                doc.build(story)
                buffer.seek(0)
                return buffer.getvalue(), "application/pdf", "PromptShield_Security_Report.pdf"
            except Exception as e:
                print(f"Error drawing PDF using reportlab: {e}")
                return b"", "text/plain", "error.txt"
        else:
            # Fallback text format if reportlab is missing
            buffer.seek(0)
            text_data = f"""
PROMPTSHIELD SECURITY AUDIT REPORT
=================================
Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Summary Stats:
- Registered Users: {users_count}
- Documents: {docs_count}
- Injection Attempts: {attempts_count}
- Blocked: {blocked_count}
- Avg Risk Score: {round(float(avg_risk), 1)}/100

Detailed logs and analysis require reportlab package. Please install it on the server.
"""
            return text_data.encode('utf-8'), "text/plain", "PromptShield_Security_Report.txt"
