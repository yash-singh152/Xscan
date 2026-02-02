from django.urls import path
from .views import (
    home,
    scan_form,
    quick_scan_view,
    deep_scan_view,
    scan_list,
    scan_detail,
    download_report,
    post_login,
    delete_scan,
    scan_progress,
    scan_status_api,
)

urlpatterns = [
    path("", home, name="home"),

    # Scan
    path("scan/", scan_form, name="scan_form"),
    path("scan/quick/", quick_scan_view, name="quick_scan"),
    path("scan/deep/", deep_scan_view, name="deep_scan"),
    path("scans/", scan_list, name="scan_list"),
    path("scan/<int:scan_id>/", scan_detail, name="scan_detail"),
    path("scan/<int:scan_id>/progress/", scan_progress, name="scan_progress"),
    path("scan/<int:scan_id>/status/", scan_status_api, name="scan_status_api"),
    path("scan/<int:scan_id>/delete/", delete_scan, name="delete_scan"),
    path(
        "scan/<int:scan_id>/download/",
        download_report,
        name="download_report"
    ),

    # After login (for free scan → account)
    path("post-login/", post_login, name="post_login"),
]
