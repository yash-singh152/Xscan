from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, FileResponse
from django.contrib import messages
import threading

from .models import Scan, Vulnerability, FreeScan
from .simple_scanner import basic_scan, deep_scan
from .pdf_genrator import generate_pdf


# -------------------------------------------------
# Utility
# -------------------------------------------------
def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


# -------------------------------------------------
# HOME PAGE (Public)
# -------------------------------------------------
def home(request):
    return render(request, "scanner/home.html")


# -------------------------------------------------
# DASHBOARD (After Login)
# -------------------------------------------------
@login_required
def dashboard(request):
    scans = Scan.objects.filter(user=request.user).order_by("-created_at")
    last_scan = scans.first()
    
    # Initialize metrics for the last scan
    threats_count = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    score = 100
    status_label = "STABLE"
    recent_threats = []

    if last_scan:
        from .models import Vulnerability
        threats = Vulnerability.objects.filter(scan=last_scan)
        threats_count = threats.count()
        
        # Severity breakdown for last scan
        critical_count = threats.filter(severity="Critical").count()
        high_count = threats.filter(severity="High").count()
        medium_count = threats.filter(severity="Medium").count()
        low_count = threats.filter(severity="Low").count()

        # threats for display
        recent_threats = threats.order_by("-id")[:5]
        
        # Calculate Security Score
        score -= (critical_count * 25)
        score -= (high_count * 15)
        score -= (medium_count * 10)
        score -= (low_count * 5)
        score = max(0, min(100, score))
        
        if score >= 90: status_label = "SECURE"
        elif score >= 70: status_label = "VULNERABLE"
        else: status_label = "CRITICAL"
    
    return render(request, "scanner/dashboard.html", {
        "scans": scans,
        "last_scan": last_scan,
        "scans_count": scans.count(),
        "threats_count": threats_count,
        "recent_threats": recent_threats,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "system_status": status_label,
        "security_score": score,
        "username": request.user.username
    })


# -------------------------------------------------
# SCAN FORM (FREE + LOGGED USERS)
# -------------------------------------------------
def scan_form(request):
    if request.method == "POST":
        url = request.POST.get("target_url")

        scan_type = request.POST.get("scan_type", "Quick")

        # ---------------- FREE USER ----------------
        if not request.user.is_authenticated:
            # Free users only get basic scan
            if scan_type == "Deep":
                 messages.warning(request, "Deep scan requires login.")
                 return redirect("login")

            free_count = FreeScan.objects.filter(
                ip_address=get_client_ip(request)
            ).count()

            if free_count >= 3:
                messages.warning(request, "Free scan limit reached. Please login.")
                return redirect("login")

            try:
                results = basic_scan(url)
            except Exception:
                messages.error(request, "Scan failed. Try again later.")
                return redirect("home")

            # Store IP and target_url
            FreeScan.objects.create(
                ip_address=get_client_ip(request).strip(),
                target_url=url
            )

            # Save results temporarily
            request.session["trial_results"] = results
            request.session["trial_url"] = url

            return redirect("login")

        # ---------------- LOGGED-IN USER ----------------


        # The following lines are placeholders from the instruction,
        # the actual scan logic is handled below in the try/except block.
        # scan_process = basic_scan if scan_type == 'Quick' else deep_scan # Placeholder for deep_scan logic
        # In a real scenario, you'd likely want to pass different arguments or call different functions
        # For now, let's assume deep_scan is implemented or we use basic_scan as a fallback if not ready
        # if scan_type == 'Deep':
        #      # TODO: Replace with actual deep scan function call when ready
        #      # For now, we reuse basic_scan but maybe valid to distinguish in the DB
        #      pass

        return _handle_scan_submission(request, scan_type)

    initial_scan_type = request.GET.get("type", "Quick")
    if initial_scan_type not in ["Quick", "Deep"]:
        initial_scan_type = "Quick"

    return render(request, "scanner/scan_form.html", {"initial_scan_type": initial_scan_type})


@login_required
def quick_scan_view(request):
    if request.method == "POST":
        return _handle_scan_submission(request, "Quick")
    return render(request, "scanner/quick_scan_form.html")

@login_required
def deep_scan_view(request):
    if request.method == "POST":
        return _handle_scan_submission(request, "Deep")
    return render(request, "scanner/deep_scan_form.html")

def _handle_scan_submission(request, scan_type):
    url = request.POST.get("target_url")
    if not url:
        return redirect(request.path)

    scan = Scan.objects.create(
        user=request.user,
        target_url=url,
        scan_type=scan_type,
        status="running",
        progress=0
    )

    # Start scan in background thread
    thread = threading.Thread(target=run_scan_background, args=(scan.id,))
    thread.daemon = True
    thread.start()

    return redirect("scan_progress", scan.id)


def run_scan_background(scan_id):
    from .models import Scan, Vulnerability # Import inside to avoid circular issues
    
    scan = Scan.objects.get(id=scan_id)
    
    def on_progress(percent):
        scan.progress = percent
        scan.save()

    try:
        if scan.scan_type == "Deep":
             results = deep_scan(scan.target_url, on_progress=on_progress)
        else:
             results = basic_scan(scan.target_url, on_progress=on_progress)

        for issue in results:
            Vulnerability.objects.create(
                scan=scan,
                title=issue["title"],
                severity=issue["severity"],
                description=issue["description"],
                mitigation=issue["mitigation"],
            )

        scan.status = "completed"
        scan.progress = 100

    except Exception:
        scan.status = "failed"

    scan.save()


@login_required
def scan_progress(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id, user=request.user)
    if scan.status == "completed":
        return redirect("scan_detail", scan.id)
    return render(request, "scanner/scan_progress.html", {"scan": scan})


@login_required
def scan_status_api(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id, user=request.user)
    return JsonResponse({
        "status": scan.status,
        "progress": scan.progress,
        "detail_url": f"/scan/{scan.id}/"
    })


# -------------------------------------------------
# SCAN HISTORY
# -------------------------------------------------
@login_required
def scan_list(request):
    scans = Scan.objects.filter(user=request.user).order_by("-created_at")
    return render(request, "scanner/scan_list.html", {"scans": scans})


# -------------------------------------------------
# SCAN DETAILS
# -------------------------------------------------
@login_required
def scan_detail(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id, user=request.user)
    vulnerabilities = Vulnerability.objects.filter(scan=scan)

    return render(
        request,
        "scanner/scan_detail.html",
        {
            "scan": scan,
            "vulnerabilities": vulnerabilities
        }
    )


# -------------------------------------------------
# DOWNLOAD PDF REPORT
# -------------------------------------------------
@login_required
def download_report(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id, user=request.user)
    vulnerabilities = Vulnerability.objects.filter(scan=scan)

    pdf_file = generate_pdf(scan, vulnerabilities)
    return FileResponse(open(pdf_file, "rb"), as_attachment=True)


# -------------------------------------------------
# POST LOGIN (FREE → ACCOUNT CONVERSION)
# -------------------------------------------------
@login_required
def post_login(request):
    results = request.session.get("trial_results")
    url = request.session.get("trial_url")

    if results and url:
        scan = Scan.objects.create(
            user=request.user,
            target_url=url,
            status="completed"
        )

        for issue in results:
            Vulnerability.objects.create(
                scan=scan,
                title=issue["title"],
                severity=issue["severity"],
                description=issue["description"],
                mitigation=issue["mitigation"],
            )

        # Clear temp data
        request.session.pop("trial_results", None)
        request.session.pop("trial_url", None)

    return redirect("dashboard")


@login_required
def delete_scan(request, scan_id):
    if request.method == "POST":
        scan = get_object_or_404(Scan, id=scan_id, user=request.user)
        scan.delete()
        messages.success(request, "Scan deleted successfully.")
    return redirect("dashboard")
