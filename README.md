# VulnScanner

**VulnScanner** is a comprehensive web-based vulnerability scanner built with Django. It provides an easy-to-use interface for identifying security weaknesses in web applications through Quick and Deep scans, offering detailed insights and PDF reporting.

## Features

*   **Dashboard**: Intuitive visual overview of recent scans, threat metrics, and overall security score.
*   **Quick Scan**: Rapidly checks for common vulnerabilities and superficial issues.
*   **Deep Scan**: Performs a thorough analysis for a comprehensive security assessment (requires authentication).
*   **PDF Reports**: Generate downloadable, detailed PDF reports for each scan result.
*   **User Accounts**: Secure sign-up and login to manage personal scan history and access deep scanning.
*   **Scan History**: Maintain a log of all past scans with easy access to detailed results.
*   **Background Scanning**: Scans run asynchronously, allowing you to navigate the site while the scan completes.

## Tech Stack

*   **Backend**: Django 6.0.1, Python 3.12+
*   **Database**: SQLite (Development) / PostgreSQL (Production)
*   **Frontend**: HTML5, CSS3, JavaScript (Bootstrap/Custom Styling)
*   **PDF Generation**: ReportLab
*   **Task Queue**: Threading for background scans
*   **Deployment**: Validated for platforms like Render

## Installation & Setup

### Prerequisites

*   Python 3.10 or higher
*   Git

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/vulnscanner.git
cd vulnscanner
```

### 2. Create and Activate Virtual Environment

**Windows:**
```bash
python -m venv venv
.\venv\Scripts\activate
```

**macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

Navigate to the directory containing `requirements.txt` (if different) and install:

```bash
pip install -r requirements.txt
```

### 4. Environment Variables

Create a `.env` file in the core project directory (alongside `settings.py` or the outer `manage.py`) with the following keys:

```env
SECRET_KEY=your_secret_key_here
DEBUG=True
DATABASE_URL=sqlite:///db.sqlite3  # Optional for local, required for prod
EMAIL_HOST_USER=your_email@gmail.com
EMAIL_HOST_PASSWORD=your_app_password
```

### 5. Database Migrations

Apply the database migrations to set up the schema:

```bash
python manage.py migrate
```

### 6. Create Superuser (Optional)

To access the Django Admin panel:

```bash
python manage.py createsuperuser
```

### 7. Run the Server

Start the local development server:

```bash
python manage.py runserver
```

Open your browser and navigate to: [http://127.0.0.1:8000](http://127.0.0.1:8000)

## Usage Guide

1.  **Home Page**: Enter a URL to start a Quick Scan immediately.
2.  **Authentication**: Click "Login" or "Register" to access the Dashboard and Deep Scan features.
3.  **Dashboard**: View your security score, recent threats, and scan history.
4.  **Running Scans**:
    *   **Quick Scan**: Fast check for common issues.
    *   **Deep Scan**: Comprehensive analysis (Registered users only).
5.  **View Results**: Click on any scan in the dashboard to see detailed vulnerability findings.
6.  **Export**: Click "Download Report" on the scan detail page to get a PDF summary.

## Deployment

The project is configured for deployment on **Render** (via `render.yaml` and `build.sh`).

**Build Command:**
```bash
./build.sh
```

**Start Command:**
```bash
gunicorn vulnscanner.wsgi:application
```

## Contributing

Contributions are welcome! Please fork the repository and submit a Pull Request with your changes.

## License

This project is licensed under the MIT License.
