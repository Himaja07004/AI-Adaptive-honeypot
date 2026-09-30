import openpyxl
from django.shortcuts import render
from django.http import HttpResponse
from .models import AttackLog
from .ml_engine import classify_threat

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')

def trigger_security_alert(log_entry):
    """Triggers high-priority alerts in the server console for critical/attack threats"""
    if "CRITICAL" in log_entry.classified_intent.upper() or "ATTACK" in log_entry.classified_intent.upper() or log_entry.risk_score >= 0.7:
        print(f"\n🚨 [AI SOC SECURITY ALERT] BREACH DETECTED! IP: {log_entry.attacker_ip} | Intent: {log_entry.classified_intent} | Risk Score: {log_entry.risk_score}\n")

def export_logs_excel(request):
    """Exports attack logs as a formatted Excel spreadsheet (.xlsx)"""
    response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    response['Content-Disposition'] = 'attachment; filename="threat_intelligence_report.xlsx"'
    
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Attack Logs"
    
    ws.append(['ID', 'Attacker IP', 'Target Path', 'Payload', 'Classified Intent', 'Risk Score', 'Timestamp'])
    
    logs = AttackLog.objects.all().values_list('id', 'attacker_ip', 'target_path', 'payload', 'classified_intent', 'risk_score', 'timestamp')
    for log in logs:
        row = list(log)
        if row[6]:
            row[6] = row[6].strftime('%Y-%m-%d %H:%M:%S')
        ws.append(row)
        
    wb.save(response)
    return response

from django.utils import timezone

def export_logs_txt(request):
    """Exports a professionally formatted and structured plain text security audit report (.txt)"""
    response = HttpResponse(content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="threat_intelligence_report.txt"'
    
    logs = AttackLog.objects.all().order_by('-timestamp')
    total_logs = logs.count()
    critical_count = logs.filter(classified_intent__icontains="CRITICAL").count()
    attack_count = logs.filter(classified_intent__icontains="ATTACK").count()
    
    # Professional Executive Header
    report_content = "=" * 70 + "\n"
    report_content += "             CYBERSECURITY THREAT INTELLIGENCE AUDIT REPORT\n"
    report_content += "             Enterprise Honeypot & SOC Analytics System\n"
    report_content += "=" * 70 + "\n\n"
    
    report_content += f" • Generation Timestamp : {timezone.now().strftime('%Y-%m-%d %H:%M:%S')} (UTC)\n"
    report_content += f" • Total Recorded Events: {total_logs}\n"
    report_content += f" • Critical High-Risk   : {critical_count}\n"
    report_content += f" • Active Attack Vectors: {attack_count}\n\n"
    report_content += "=" * 70 + "\n\n"
    report_content += " DETAILED INCIDENT LOGS\n\n"
    
    # Detailed Incident Entries
    for log in logs:
        formatted_time = log.timestamp.strftime('%Y-%m-%d %H:%M:%S') if log.timestamp else "N/A"
        report_content += f"┌─ Incident ID    : #{log.id}\n"
        report_content += f"├─ Attacker IP    : {log.attacker_ip}\n"
        report_content += f"├─ Target Path    : {log.target_path}\n"
        report_content += f"├─ Payload Data   : {log.payload}\n"
        report_content += f"├─ Threat Intent  : {log.classified_intent}\n"
        report_content += f"├─ AI Risk Score  : {log.risk_score}\n"
        report_content += f"└─ Timestamp      : {formatted_time}\n"
        report_content += "-" * 70 + "\n"
        
    report_content += "\n[END OF REPORT - CONFIDENTIAL SECURITY AUDIT]\n"
    
    response.write(report_content)
    return response

def honeypot_trap(request):
    target_path = request.path.rstrip('/')  # Normalizes paths to prevent trailing slash mismatches
    if target_path == '/favicon.ico':
        return HttpResponse(status=204)

    # STATS DASHBOARD WITH DATE/MONTH FILTERING
    if request.GET.get('view') == 'stats':
        logs = AttackLog.objects.all().order_by('-timestamp')
        
        filter_date = request.GET.get('date')
        if filter_date:
            logs = logs.filter(timestamp__date=filter_date)
            
        filter_month = request.GET.get('month')
        if filter_month:
            try:
                year, month = filter_month.split('-')
                logs = logs.filter(timestamp__year=year, timestamp__month=month)
            except ValueError:
                pass
                
        return render(request, 'honeypot/dashboard.html', {'logs': logs})

    error_message = None

    # VIEW VAULT PASSWORD GATE & CATEGORY ROUTING (/download-secrets/)
    if target_path == '/download-secrets':
        attacker_ip = get_client_ip(request)
        VAULT_PASS = "Admin@123"   
        doc_type = request.GET.get('doc', 'finance')
        session_id = request.COOKIES.get('soc_session', 'active')

        if request.method == 'POST':
            vault_pass = request.POST.get('password', '')
            payload_data = f"vault_password={vault_pass}&doc={doc_type}"
            
            if vault_pass == VAULT_PASS:
                log_entry = AttackLog.objects.create(
                    attacker_ip=attacker_ip,
                    target_path=request.path,
                    payload=payload_data,
                    classified_intent=f"CRITICAL: Attacker Successfully Authenticated to {doc_type.upper()} Vault",
                    risk_score=0.98,
                    session_id=session_id
                )
                trigger_security_alert(log_entry)
                return render(request, 'honeypot/vault_success.html', {'doc_type': doc_type})
            else:
                log_entry = AttackLog.objects.create(
                    attacker_ip=attacker_ip,
                    target_path=request.path,
                    payload=payload_data,
                    classified_intent="ATTACK: Post-Auth Vault Password Brute-Force",
                    risk_score=0.85,
                    session_id=session_id
                )
                trigger_security_alert(log_entry)
                return render(request, 'honeypot/breached.html', {'error': 'Invalid password. Access denied.', 'doc_type': doc_type})
        
        return render(request, 'honeypot/breached.html', {'doc_type': doc_type})

    # LOGIN PORTAL HANDLING (Matches /login.php, root /, or blank paths)
    if target_path in ['', '/login.php'] or request.GET:
        attacker_ip = get_client_ip(request)
        WEAK_USER = "@security_admin123"
        WEAK_PASS = "SecureAdmin@1999"
        session_id = request.COOKIES.get('soc_session', 'active')

        if request.method == 'POST':
            username = request.POST.get('user', '')
            password = request.POST.get('password', '')
            payload_data = f"user={username}&password={password}"
            
            if username == WEAK_USER and password == WEAK_PASS:
                log_entry = AttackLog.objects.create(
                    attacker_ip=attacker_ip,
                    target_path=request.path,
                    payload=payload_data,
                    classified_intent="SUSPICIOUS: Weak Credential Match (Monitoring Active)",
                    risk_score=0.45,
                    session_id=session_id
                )
                trigger_security_alert(log_entry)
                return render(request, 'honeypot/success.html', {'username': username})
            
            else:
                intent, risk_score = classify_threat(payload_data)
                log_entry = AttackLog.objects.create(
                    attacker_ip=attacker_ip,
                    target_path=request.path,
                    payload=payload_data,
                    classified_intent=intent,
                    risk_score=risk_score,
                    session_id=session_id
                )
                trigger_security_alert(log_entry)
                error_message = "Invalid username or password."
                return render(request, 'honeypot/login.php', {'error': error_message})

        else:
            payload_data = request.META.get('QUERY_STRING', '')
            if payload_data:
                intent, risk_score = classify_threat(payload_data)
                AttackLog.objects.create(
                    attacker_ip=attacker_ip,
                    target_path=request.path,
                    payload=payload_data,
                    classified_intent=intent,
                    risk_score=risk_score,
                    session_id=session_id
                )

    return render(request, 'honeypot/login.php', {'error': error_message})