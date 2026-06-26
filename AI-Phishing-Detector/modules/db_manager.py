import sqlite3

DB_NAME = "phishing_scans.db"


def init_db():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            verdict TEXT,
            confidence REAL,
            risk_score INTEGER,
            urls TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_scan(
        verdict,
        confidence,
        risk_score,
        urls):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans
        (
            verdict,
            confidence,
            risk_score,
            urls
        )
        VALUES (?, ?, ?, ?)
    """, (
        verdict,
        confidence,
        risk_score,
        urls
    ))

    conn.commit()
    conn.close()


def get_scans():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def get_dashboard_stats():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
    """)

    total_scans = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE verdict LIKE '%Phishing%'
    """)

    phishing_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE verdict LIKE '%Legitimate%'
    """)

    legitimate_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT AVG(risk_score)
        FROM scans
    """)

    avg_risk = cursor.fetchone()[0]

    conn.close()

    if avg_risk is None:
        avg_risk = 0

    return {

        "total_scans":
            total_scans,

        "phishing_count":
            phishing_count,

        "legitimate_count":
            legitimate_count,

        "avg_risk":
            round(avg_risk, 2)
    }