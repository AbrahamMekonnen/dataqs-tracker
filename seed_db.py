import csv
import sqlite3
import os

here = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(here, "leads.db")
csv_path = os.path.join(here, "dataqs_lead_list.csv")

con = sqlite3.connect(db_path)
cur = con.cursor()
cur.execute("DROP TABLE IF EXISTS leads")
cur.execute("""
CREATE TABLE leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dot_number TEXT,
    company TEXT,
    dba TEXT,
    city TEXT,
    state TEXT,
    phone TEXT,
    trucks INTEGER,
    drivers TEXT,
    alert_basics TEXT,
    n_alerts INTEGER,
    inspections INTEGER,
    driver_oos TEXT,
    vehicle_oos TEXT,
    sms_profile TEXT,
    status TEXT DEFAULT 'New',
    priority TEXT,
    first_contact TEXT,
    last_contact TEXT,
    audit_sent TEXT,
    outcome TEXT,
    next_step TEXT,
    notes TEXT
)
""")

with open(csv_path, newline="", encoding="utf-8-sig") as f:
    rows = list(csv.DictReader(f))

for r in rows:
    cur.execute(
        """INSERT INTO leads
        (dot_number, company, dba, city, state, phone, trucks, drivers,
         alert_basics, n_alerts, inspections, driver_oos, vehicle_oos,
         sms_profile, status)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'New')""",
        (
            r["dot_number"], r["company"], r["dba"], r["city"], r["state"],
            r["phone"], int(r["trucks"] or 0), r["drivers"], r["alert_basics"],
            int(r["n_alerts"] or 0), int(r["inspections"] or 0),
            r["driver_oos"], r["vehicle_oos"], r["sms_profile"],
        ),
    )

con.commit()
n = cur.execute("SELECT COUNT(*) FROM leads").fetchone()[0]
print("seeded", n, "leads into", db_path)
con.close()
