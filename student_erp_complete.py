# student_erp_complete.py
import streamlit as st
import sqlite3
import os
from datetime import datetime, timedelta
import bcrypt
import jwt
import smtplib
from email.message import EmailMessage
import matplotlib.pyplot as plt
from pathlib import Path
import json

# Optional twilio import (commented out by default)
try:
    from twilio.rest import Client as TwilioClient
    TWILIO_AVAILABLE = True
except Exception:
    TWILIO_AVAILABLE = False

# ------------------------
# CONFIG
# ------------------------
DB_PATH = "student_erp_complete.db"
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
JWT_SECRET = "replace-this-with-a-strong-secret"  # change in production
JWT_ALGORITHM = "HS256"
JWT_EXP_DAYS = 1

# Helper: connect
def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

# ------------------------
# DB INIT
# ------------------------
def init_db():
    conn = get_conn()
    c = conn.cursor()

    # users: role in ('admin','student','faculty','parent')
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password_hash TEXT,
        role TEXT,
        course TEXT,
        phone TEXT,
        parent_email TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS marks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER,
        subject TEXT,
        marks INTEGER,
        term TEXT,
        created_at TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER,
        date TEXT,
        status TEXT,
        created_at TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS timetable (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course TEXT,
        day TEXT,
        subject TEXT,
        time TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        date TEXT,
        channel TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS fees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER,
        amount REAL,
        status TEXT,
        created_at TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        student_id INTEGER,
        uploader_role TEXT,
        upload_time TEXT,
        filepath TEXT
    )""")

    # Admin default (if not exists)
    # password is 'admin123' hashed
    admin_pass = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
    try:
        c.execute("INSERT OR IGNORE INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                  ("Default Admin","admin@example.com", admin_pass, "admin"))
    except Exception:
        pass

    conn.commit()
    conn.close()

init_db()

# ------------------------
# SECURITY / AUTH HELPERS
# ------------------------
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def check_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False

def create_jwt(payload: dict, days=JWT_EXP_DAYS) -> str:
    p = payload.copy()
    p["exp"] = datetime.utcnow() + timedelta(days=days)
    token = jwt.encode(p, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def decode_jwt(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None

# ------------------------
# EMAIL & SMS (configurable)
# ------------------------
def send_email_smtp(to_email: str, subject: str, body: str, smtp_config: dict) -> bool:
    """
    smtp_config example:
    {
      "host": "smtp.gmail.com",
      "port": 587,
      "username": "you@domain.com",
      "password": "yourpassword",
      "use_tls": True
    }
    """
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = smtp_config["username"]
        msg["To"] = to_email
        msg.set_content(body)

        server = smtplib.SMTP(smtp_config["host"], smtp_config.get("port", 587))
        if smtp_config.get("use_tls", True):
            server.starttls()
        server.login(smtp_config["username"], smtp_config["password"])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        st.error(f"Email send failed: {e}")
        return False

def send_sms_placeholder(to_phone: str, body: str, twilio_config: dict = None) -> bool:
    """
    Placeholder SMS sender. If twilio_config provided, will attempt Twilio send.
    twilio_config example:
    {
      "account_sid": "...",
      "auth_token": "...",
      "from_phone": "+1234567890"
    }
    """
    if twilio_config and TWILIO_AVAILABLE:
        try:
            client = TwilioClient(twilio_config["account_sid"], twilio_config["auth_token"])
            message = client.messages.create(
                body=body,
                from_=twilio_config["from_phone"],
                to=to_phone
            )
            return True
        except Exception as e:
            st.error(f"Twilio send failed: {e}")
            return False
    else:
        # fallback: log to notifications table as "sms" channel
        conn = get_conn()
        c = conn.cursor()
        c.execute("INSERT INTO notifications(message,date,channel) VALUES(?,?,?)",
                  (f"[SMS to {to_phone}] {body}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "sms"))
        conn.commit()
        conn.close()
        return True

# ------------------------
# FILE UPLOAD HELPERS
# ------------------------
def save_upload(uploaded_file, student_id, uploader_role):
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    sanitized = uploaded_file.name.replace(" ", "_")
    filename = f"{ts}_{sanitized}"
    path = UPLOAD_DIR / filename
    with open(path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO uploads(filename, student_id, uploader_role, upload_time, filepath) VALUES(?,?,?,?,?)",
              (uploaded_file.name, student_id, uploader_role, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), str(path)))
    conn.commit()
    conn.close()
    return str(path)

# ------------------------
# UI: SETTINGS (SMTP/TWILIO)
# ------------------------
def settings_page():
    st.header("Settings & Integrations")
    st.info("Configure SMTP for email sending, and Twilio for SMS sending. These settings are stored locally in a JSON file `settings.json`.")

    settings = {}
    settings_path = Path("settings.json")
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except Exception:
            settings = {}

    st.subheader("SMTP (Email)")
    smtp_host = st.text_input("SMTP Host", value=settings.get("smtp", {}).get("host", "smtp.gmail.com"))
    smtp_port = st.number_input("SMTP Port", value=int(settings.get("smtp", {}).get("port", 587)))
    smtp_user = st.text_input("SMTP Username", value=settings.get("smtp", {}).get("username", ""))
    smtp_pass = st.text_input("SMTP Password", value=settings.get("smtp", {}).get("password", ""), type="password")
    smtp_tls = st.checkbox("Use TLS", value=settings.get("smtp", {}).get("use_tls", True))

    st.subheader("Twilio (SMS) - optional")
    tw_sid = st.text_input("Twilio Account SID", value=settings.get("twilio", {}).get("account_sid", ""))
    tw_token = st.text_input("Twilio Auth Token", value=settings.get("twilio", {}).get("auth_token", ""), type="password")
    tw_from = st.text_input("Twilio From Phone (E.164)", value=settings.get("twilio", {}).get("from_phone", ""))

    if st.button("Save Settings"):
        new = {
            "smtp": {"host": smtp_host, "port": smtp_port, "username": smtp_user, "password": smtp_pass, "use_tls": smtp_tls},
            "twilio": {"account_sid": tw_sid, "auth_token": tw_token, "from_phone": tw_from}
        }
        settings_path.write_text(json.dumps(new))
        st.success("Settings saved to settings.json")

    if settings_path.exists():
        st.subheader("Current settings preview (local file)")
        st.write(settings_path.read_text())

# ------------------------
# ADMIN FEATURES
# ------------------------
def admin_panel():
    st.header("Admin Dashboard")
    menu = st.sidebar.selectbox("Admin Menu", ["Manage Users","Manage Marks","Attendance","Timetable","Notifications","Fees","Uploads","Settings"])
    if menu == "Manage Users":
        admin_manage_users()
    elif menu == "Manage Marks":
        admin_manage_marks()
    elif menu == "Attendance":
        admin_manage_attendance()
    elif menu == "Timetable":
        admin_manage_timetable()
    elif menu == "Notifications":
        admin_manage_notifications()
    elif menu == "Fees":
        admin_manage_fees()
    elif menu == "Uploads":
        admin_manage_uploads()
    elif menu == "Settings":
        settings_page()

def admin_manage_users():
    st.subheader("All users")
    conn = get_conn(); c = conn.cursor()
    users = c.execute("SELECT id, name, email, role, course, phone, parent_email FROM users").fetchall()
    conn.close()
    st.table(users)

    with st.form("create_user_form"):
        st.write("Create user (Admin/Student/Faculty/Parent)")
        name = st.text_input("Name")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        role = st.selectbox("Role", ["student","faculty","parent","admin"])
        course = st.selectbox("Course (if student)", ["", "B.Tech","BBA","BCA","MBA","MCA"])
        phone = st.text_input("Phone")
        parent_email = st.text_input("Parent Email (if student)")

        submitted = st.form_submit_button("Create User")
        if submitted:
            if not name or not email or not password:
                st.error("Name, email and password required")
            else:
                pwd_hash = hash_password(password)
                conn = get_conn(); c = conn.cursor()
                try:
                    c.execute("INSERT INTO users(name,email,password_hash,role,course,phone,parent_email) VALUES(?,?,?,?,?,?,?)",
                              (name,email,pwd_hash,role, course or None, phone or None, parent_email or None))
                    conn.commit()
                    st.success("User created")
                except sqlite3.IntegrityError:
                    st.error("Email already exists")
                conn.close()

def admin_manage_marks():
    st.subheader("Add / View Marks")
    conn = get_conn(); c = conn.cursor()
    students = c.execute("SELECT id, name FROM users WHERE role='student'").fetchall()
    conn.close()
    if not students:
        st.info("No students, create users first.")
        return
    student_map = {f"{s[1]} (id:{s[0]})": s[0] for s in students}
    sel = st.selectbox("Select Student", list(student_map.keys()))
    student_id = student_map[sel]
    subject = st.text_input("Subject")
    marks = st.number_input("Marks", min_value=0, max_value=100)
    term = st.text_input("Term (e.g., Mid, Final)", value="Term1")

    if st.button("Add Mark"):
        conn = get_conn(); c = conn.cursor()
        c.execute("INSERT INTO marks(student_id,subject,marks,term,created_at) VALUES(?,?,?,?,?)",
                  (student_id, subject, marks, term, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit(); conn.close()
        st.success("Marks added")

    # View student's marks
    conn = get_conn(); c = conn.cursor()
    rows = c.execute("SELECT subject, marks, term, created_at FROM marks WHERE student_id=? ORDER BY created_at DESC", (student_id,)).fetchall()
    conn.close()
    st.table(rows)

    # chart
    if rows:
        subjects = [r[0] for r in rows]
        scores = [r[1] for r in rows]
        fig, ax = plt.subplots()
        ax.bar(subjects, scores)
        ax.set_ylabel("Marks")
        ax.set_title("Marks distribution")
        st.pyplot(fig)

def admin_manage_attendance():
    st.subheader("Mark Attendance")
    conn = get_conn(); c = conn.cursor()
    students = c.execute("SELECT id, name, course FROM users WHERE role='student'").fetchall()
    conn.close()
    if not students:
        st.info("No students found.")
        return
    student_map = {f"{s[1]} ({s[2]}) id:{s[0]}": s[0] for s in students}
    sel = st.selectbox("Select Student", list(student_map.keys()))
    student_id = student_map[sel]
    status = st.selectbox("Status", ["Present","Absent"])
    date = st.date_input("Date", value=datetime.today())

    if st.button("Record Attendance"):
        conn = get_conn(); c = conn.cursor()
        c.execute("INSERT INTO attendance(student_id,date,status,created_at) VALUES(?,?,?,?)",
                  (student_id, date.strftime("%Y-%m-%d"), status, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit(); conn.close()
        st.success("Attendance recorded")

def admin_manage_timetable():
    st.subheader("Add Timetable Entry")
    course = st.selectbox("Course", ["B.Tech","BBA","BCA","MBA","MCA"])
    day = st.selectbox("Day", ["Monday","Tuesday","Wednesday","Thursday","Friday"])
    subj = st.text_input("Subject")
    time = st.text_input("Time (e.g., 10:00-11:00)")
    if st.button("Add Timetable"):
        conn = get_conn(); c = conn.cursor()
        c.execute("INSERT INTO timetable(course,day,subject,time) VALUES(?,?,?,?)", (course, day, subj, time))
        conn.commit(); conn.close()
        st.success("Timetable entry added")
    conn = get_conn(); c = conn.cursor()
    rows = c.execute("SELECT day, subject, time FROM timetable WHERE course=? ORDER BY day", (course,)).fetchall()
    conn.close()
    st.table(rows)

def admin_manage_notifications():
    st.subheader("Post Notification (Email/SMS/Notice)")
    message = st.text_area("Message")
    channel = st.selectbox("Channel", ["notice","email","sms"])
    target = st.selectbox("Target", ["All Students","Specific Student"])
    student_id = None
    if target == "Specific Student":
        conn = get_conn(); c = conn.cursor()
        students = c.execute("SELECT id, name FROM users WHERE role='student'").fetchall(); conn.close()
        sel = st.selectbox("Select Student", [f"{s[1]} (id:{s[0]})" for s in students])
        student_id = int(sel.split("id:")[-1].strip(")"))

    if st.button("Send Notification"):
        conn = get_conn(); c = conn.cursor()
        c.execute("INSERT INTO notifications(message,date,channel) VALUES(?,?,?)", (message, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), channel))
        conn.commit(); conn.close()
        st.success("Notification stored")
        # If email or sms, attempt sends based on settings.json
        settings_path = Path("settings.json")
        settings = {}
        if settings_path.exists():
            try:
                settings = json.loads(settings_path.read_text())
            except:
                settings = {}
        if channel == "email":
            smtp = settings.get("smtp")
            if target == "All Students":
                conn = get_conn(); c = conn.cursor()
                students = c.execute("SELECT email FROM users WHERE role='student'").fetchall(); conn.close()
                for s in students:
                    if s[0]:
                        send_email_smtp(s[0], "College Notification", message, smtp)
            else:
                conn = get_conn(); c = conn.cursor()
                email = c.execute("SELECT email FROM users WHERE id=?", (student_id,)).fetchone()[0]; conn.close()
                send_email_smtp(email, "College Notification", message, smtp)
        elif channel == "sms":
            tw = settings.get("twilio")
            if target == "All Students":
                conn = get_conn(); c = conn.cursor()
                phones = c.execute("SELECT phone FROM users WHERE role='student'").fetchall(); conn.close()
                for p in phones:
                    if p[0]:
                        send_sms_placeholder(p[0], message, tw)
            else:
                conn = get_conn(); c = conn.cursor()
                phone = c.execute("SELECT phone FROM users WHERE id=?", (student_id,)).fetchone()[0]; conn.close()
                send_sms_placeholder(phone, message, tw)

def admin_manage_fees():
    st.subheader("Fees Management")
    conn = get_conn(); c = conn.cursor()
    students = c.execute("SELECT id, name FROM users WHERE role='student'").fetchall(); conn.close()
    if not students:
        st.info("No students found")
        return
    student_map = {f"{s[1]} (id:{s[0]})": s[0] for s in students}
    sel = st.selectbox("Select Student", list(student_map.keys()))
    student_id = student_map[sel]
    amount = st.number_input("Amount", min_value=0.0)
    status = st.selectbox("Status", ["Paid","Unpaid"])
    if st.button("Record Fee"):
        conn = get_conn(); c = conn.cursor()
        c.execute("INSERT INTO fees(student_id,amount,status,created_at) VALUES(?,?,?,?)", (student_id, amount, status, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit(); conn.close()
        st.success("Fee recorded")

def admin_manage_uploads():
    st.subheader("Uploaded Files")
    conn = get_conn(); c = conn.cursor()
    rows = c.execute("SELECT id, filename, student_id, uploader_role, upload_time, filepath FROM uploads ORDER BY upload_time DESC").fetchall()
    conn.close()
    st.table(rows)

# ------------------------
# STUDENT / FACULTY / PARENT PAGES
# ------------------------
def student_dashboard(user):
    st.header(f"Welcome, {user['name']} (Student)")
    menu = st.sidebar.selectbox("Menu", ["Profile","My Marks","Attendance","Timetable","Upload Document","Notifications","Fees","Report Card"])
    if menu == "Profile":
        st.subheader("Profile")
        st.write(user)
    elif menu == "My Marks":
        student_marks_view(user['id'])
    elif menu == "Attendance":
        student_attendance_view(user['id'])
    elif menu == "Timetable":
        show_timetable_for_course(user.get("course"))
    elif menu == "Upload Document":
        student_upload_doc(user['id'])
    elif menu == "Notifications":
        show_notifications()
    elif menu == "Fees":
        show_fees_for_student(user['id'])
    elif menu == "Report Card":
        generate_report_card(user['id'])

def faculty_dashboard(user):
    st.header(f"Welcome, {user['name']} (Faculty)")
    menu = st.sidebar.selectbox("Menu", ["Profile","Manage Marks","Mark Attendance","Upload Material","Notifications"])
    if menu == "Profile":
        st.write(user)
    elif menu == "Manage Marks":
        faculty_manage_marks()
    elif menu == "Mark Attendance":
        faculty_mark_attendance()
    elif menu == "Upload Material":
        faculty_upload_material(user)
    elif menu == "Notifications":
        show_notifications()

def parent_dashboard(user):
    st.header(f"Welcome, {user['name']} (Parent)")
    # parent user object: parent_email likely stored as their email; we find children by parent_email
    conn = get_conn(); c = conn.cursor()
    children = c.execute("SELECT id, name, email, course FROM users WHERE parent_email=?", (user['email'],)).fetchall()
    conn.close()
    if not children:
        st.info("No linked children accounts found.")
        return
    child_map = {f"{c[1]} ({c[3]}) id:{c[0]}": c[0] for c in children}
    sel = st.selectbox("Select Child", list(child_map.keys()))
    child_id = child_map[sel]
    view = st.selectbox("View", ["Profile","Marks","Attendance","Fees","Report Card"])
    if view == "Profile":
        conn = get_conn(); c = conn.cursor()
        r = c.execute("SELECT id, name, email, course FROM users WHERE id=?", (child_id,)).fetchone(); conn.close()
        st.write({"id": r[0], "name": r[1], "email": r[2], "course": r[3]})
    elif view == "Marks":
        student_marks_view(child_id)
    elif view == "Attendance":
        student_attendance_view(child_id)
    elif view == "Fees":
        show_fees_for_student(child_id)
    elif view == "Report Card":
        generate_report_card(child_id)

# ------------------------
# small student/faculty helpers
# ------------------------
def student_marks_view(student_id):
    conn = get_conn(); c = conn.cursor()
    rows = c.execute("SELECT subject, marks, term FROM marks WHERE student_id=?", (student_id,)).fetchall(); conn.close()
    st.table(rows if rows else [["No marks recorded"]])
    # chart
    if rows:
        subjects = [r[0] for r in rows]
        scores = [r[1] for r in rows]
        fig, ax = plt.subplots()
        ax.plot(subjects, scores, marker='o')
        ax.set_ylim(0,100)
        ax.set_title("Performance Trend")
        st.pyplot(fig)

def student_attendance_view(student_id):
    conn = get_conn(); c = conn.cursor()
    rows = c.execute("SELECT date, status FROM attendance WHERE student_id=?", (student_id,)).fetchall(); conn.close()
    st.table(rows if rows else [["No attendance recorded"]])
    if rows:
        dates = [r[0] for r in rows]
        statuses = [1 if r[1].lower()=="present" else 0 for r in rows]
        fig, ax = plt.subplots()
        ax.plot(dates, statuses, marker='o')
        ax.set_title("Attendance (1 = Present)")
        st.pyplot(fig)

def show_timetable_for_course(course):
    if not course:
        st.info("No course assigned")
        return
    conn = get_conn(); c = conn.cursor()
    rows = c.execute("SELECT day, subject, time FROM timetable WHERE course=? ORDER BY day", (course,)).fetchall(); conn.close()
    st.table(rows if rows else [["No timetable entries"]])

def student_upload_doc(student_id):
    st.subheader("Upload Document (assignment/hallticket/etc)")
    uploaded = st.file_uploader("Choose file", type=None)
    if uploaded:
        path = save_upload(uploaded, student_id, "student")
        st.success(f"Saved to {path}")

def faculty_manage_marks():
    st.subheader("Faculty: Add Marks")
    conn = get_conn(); c = conn.cursor()
    students = c.execute("SELECT id, name FROM users WHERE role='student'").fetchall(); conn.close()
    if not students:
        st.info("No students to grade")
        return
    student_map = {f"{s[1]} id:{s[0]}": s[0] for s in students}
    sel = st.selectbox("Select Student", list(student_map.keys()))
    student_id = student_map[sel]
    subject = st.text_input("Subject")
    marks = st.number_input("Marks", 0, 100)
    term = st.text_input("Term", value="Term1")
    if st.button("Add"):
        conn = get_conn(); c = conn.cursor()
        c.execute("INSERT INTO marks(student_id,subject,marks,term,created_at) VALUES(?,?,?,?,?)", (student_id,subject,marks,term,datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit(); conn.close(); st.success("Added")

def faculty_mark_attendance():
    st.subheader("Faculty: Mark Attendance")
    conn = get_conn(); c = conn.cursor()
    students = c.execute("SELECT id, name FROM users WHERE role='student'").fetchall(); conn.close()
    student_map = {f"{s[1]} id:{s[0]}": s[0] for s in students}
    sel = st.selectbox("Select Student", list(student_map.keys()))
    student_id = student_map[sel]
    status = st.selectbox("Status", ["Present","Absent"])
    date = st.date_input("Date", value=datetime.today())
    if st.button("Mark"):
        conn = get_conn(); c = conn.cursor()
        c.execute("INSERT INTO attendance(student_id,date,status,created_at) VALUES(?,?,?,?)", (student_id, date.strftime("%Y-%m-%d"), status, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit(); conn.close(); st.success("Marked")

def faculty_upload_material(user):
    st.subheader("Upload Material for students")
    course = st.selectbox("Course to target", ["B.Tech","BBA","BCA","MBA","MCA"])
    uploaded = st.file_uploader("Material file")
    if uploaded:
        path = save_upload(uploaded, None, "faculty")
        st.success(f"Saved to {path}")

def show_notifications():
    conn = get_conn(); c = conn.cursor()
    rows = c.execute("SELECT message, date, channel FROM notifications ORDER BY date DESC LIMIT 50").fetchall(); conn.close()
    st.table(rows if rows else [["No notifications"]])

def show_fees_for_student(student_id):
    conn = get_conn(); c = conn.cursor()
    rows = c.execute("SELECT amount, status, created_at FROM fees WHERE student_id=?", (student_id,)).fetchall(); conn.close()
    st.table(rows if rows else [["No fee records"]])

def generate_report_card(student_id):
    conn = get_conn(); c = conn.cursor()
    rows = c.execute("SELECT subject, marks FROM marks WHERE student_id=?", (student_id,)).fetchall(); conn.close()
    if not rows:
        st.info("No marks to generate report card")
        return
    total = sum(r[1] for r in rows)
    avg = total / len(rows)
    st.subheader("Report Card")
    st.table(rows)
    st.write(f"Total: {total}")
    st.write(f"Average: {avg:.2f}")

# ------------------------
# AUTH UI (Registration / Login)
# ------------------------
def register_user_ui():
    st.header("Register New User")
    with st.form("register_form"):
        name = st.text_input("Full name")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        role = st.selectbox("Role", ["student","parent","faculty"])
        course = ""
        parent_email = ""
        phone = st.text_input("Phone")
        if role == "student":
            course = st.selectbox("Course", ["B.Tech","BBA","BCA","MBA","MCA"])
            parent_email = st.text_input("Parent Email")
        submitted = st.form_submit_button("Register")
        if submitted:
            if not name or not email or not password:
                st.error("Name, email and password are required")
            else:
                pwd_hash = hash_password(password)
                conn = get_conn(); c = conn.cursor()
                try:
                    c.execute("INSERT INTO users(name,email,password_hash,role,course,phone,parent_email) VALUES(?,?,?,?,?,?,?)",
                              (name,email,pwd_hash,role, course or None, phone or None, parent_email or None))
                    conn.commit(); conn.close()
                    st.success("Registered. Please login.")
                except sqlite3.IntegrityError:
                    st.error("Email already used")

def login_ui():
    st.header("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        conn = get_conn(); c = conn.cursor()
        row = c.execute("SELECT id, name, email, password_hash, role, course FROM users WHERE email=?", (email,)).fetchone(); conn.close()
        if not row:
            st.error("No account with that email")
            return
        user = {"id": row[0], "name": row[1], "email": row[2], "password_hash": row[3], "role": row[4], "course": row[5]}
        if check_password(password, user["password_hash"]):
            # create JWT and store session
            token = create_jwt({"user_id": user["id"], "role": user["role"]})
            st.session_state["jwt"] = token
            st.session_state["user"] = user
            st.success("Logged in")
        else:
            st.error("Invalid credentials")

def logout():
    if "jwt" in st.session_state: del st.session_state["jwt"]
    if "user" in st.session_state: del st.session_state["user"]
    st.experimental_rerun()

# ------------------------
# APP LAYOUT & Routing
# ------------------------
def main():
    st.title("🎓 Student ERP — Complete")
    menu = st.sidebar.selectbox("Top", ["Home","Register","Login","Settings (admin only)"])
    if "user" in st.session_state:
        user = st.session_state["user"]
        role = user["role"]
        st.sidebar.markdown(f"**Logged in:** {user['name']} ({role})")
        if st.sidebar.button("Logout"):
            logout()
        # Route by role
        if role == "admin":
            admin_panel()
        elif role == "student":
            student_dashboard(user)
        elif role == "faculty":
            faculty_dashboard(user)
        elif role == "parent":
            parent_dashboard(user)
        else:
            st.info("Unknown role.")
    else:
        if menu == "Home":
            st.write("Welcome. Use Register or Login from the sidebar.")
            st.markdown("- Admin default: admin@example.com / admin123")
        elif menu == "Register":
            register_user_ui()
        elif menu == "Login":
            login_ui()
        elif menu == "Settings (admin only)":
            settings_page()

if __name__ == "__main__":
    main()
