"""Audit engine: pulls a carrier's public FMCSA inspection/violation history,
applies challengeability rules, and returns structured findings for rendering."""
import json
import sqlite3
from datetime import datetime, timedelta

import requests

VIOL_URL = "https://data.transportation.gov/resource/8mt8-2mdr.json"
INSP_URL = "https://data.transportation.gov/resource/rbkj-cgst.json"

# Careful, non-absolute language (per review): "may affect", not "will cost you".
BASIC_CONSEQUENCE = {
    "Unsafe Driving": "one of the indicators brokers look at before assigning loads",
    "Hours-of-Service Compliance": "may draw additional roadside-inspection attention",
    "Driver Fitness": "may receive additional attention from insurers and brokers",
    "Controlled Substances/Alcohol": "may draw added scrutiny from shippers and insurers",
    "Vehicle Maintenance": "the most common alert, and often the most document-fixable",
}


def _parse_date(s):
    try:
        return datetime.strptime(s.strip(), "%d-%b-%y")
    except Exception:
        return None


def fetch_history(dot_number, con):
    """Fetch violations + inspections for a DOT number, with SQLite cache."""
    con.execute("""CREATE TABLE IF NOT EXISTS audit_cache
                   (dot_number TEXT PRIMARY KEY, fetched_at TEXT,
                    viols TEXT, insps TEXT)""")
    row = con.execute("SELECT fetched_at, viols, insps FROM audit_cache WHERE dot_number=?",
                      (dot_number,)).fetchone()
    if row:
        return json.loads(row[1]), json.loads(row[2]), row[0]
    viols = requests.get(VIOL_URL, params={"dot_number": dot_number, "$limit": "2000"},
                         timeout=60).json()
    insps = requests.get(INSP_URL, params={"dot_number": dot_number, "$limit": "2000"},
                         timeout=60).json()
    fetched = datetime.now().strftime("%Y-%m-%d %H:%M")
    con.execute("INSERT OR REPLACE INTO audit_cache VALUES (?,?,?,?)",
                (dot_number, fetched, json.dumps(viols), json.dumps(insps)))
    con.commit()
    return viols, insps, fetched


_TITLE_KEYWORDS = [
    ("speeding", "Speeding"),
    ("seat belt", "Seat belt not used"),
    ("medical", "Medical certificate issue"),
    ("record of duty status", "Logbook (HOS) issue"),
    ("rods", "Logbook (HOS) issue"),
    ("hours of service", "Hours-of-service issue"),
    ("logbook", "Logbook (HOS) issue"),
    ("lane restriction", "Lane restriction"),
    ("traffic control device", "Failed to obey traffic control"),
    ("follow", "Following too closely"),
    ("power steering", "Steering issue"),
    ("steering", "Steering issue"),
    ("turn signal", "Turn-signal defect"),
    ("stop lamp", "Stop-lamp defect"),
    ("marker lamp", "Marker-lamp defect"),
    ("headlamp", "Headlamp defect"),
    ("lighting", "Lighting defect"),
    ("tire", "Tire issue"),
    ("brake", "Brake issue"),
    ("suspension", "Suspension issue"),
    ("cargo", "Cargo securement"),
    ("fire extinguisher", "Fire extinguisher"),
    ("placard", "Placarding issue"),
    ("mud", "Mudflap issue"),
    ("wheel", "Wheel issue"),
    ("periodic inspection", "Periodic inspection missing"),
    ("cdl", "License / CDL issue"),
    ("license", "License / CDL issue"),
    ("restriction", "License restriction"),
    ("drug", "Controlled-substance item"),
    ("alcohol", "Alcohol item"),
    ("move over", "Move-over law"),
    ("emergency equipment", "Emergency equipment"),
    ("inspection report", "Inspection report item"),
]


def short_title(section, group):
    """Plain-English one-liner from the long government description."""
    s = (section or group or "").lower()
    for kw, title in _TITLE_KEYWORDS:
        if kw in s:
            return title
    base = (section or group or "Violation").split(" - ", 1)[-1]
    return (base[:38] + "…") if len(base) > 40 else base


def analyze(viols, insps, alert_basics):
    """Rule-based challengeability analysis. Returns findings + summary.

    Repeated (code, date, unit) rows in the public data are collapsed into one
    finding with a count, so the report never looks padded with duplicates.
    """
    now = datetime.now()
    alert_set = set((alert_basics or "").split("|"))
    basic_map = {"Unsafe Driving": "UnsafeDriving", "Hours-of-Service Compliance": "HOS",
                 "Driver Fitness": "DriverFitness",
                 "Controlled Substances/Alcohol": "DrugsAlcohol",
                 "Vehicle Maintenance": "VehicleMaint"}

    # group identical rows (same code + date + unit)
    groups = {}
    order = []
    for v in viols:
        key = (v.get("viol_code"), v.get("insp_date"), v.get("viol_unit"))
        if key not in groups:
            groups[key] = {"v": v, "count": 0}
            order.append(key)
        groups[key]["count"] += 1

    findings = []
    basic_severity = {}
    total_in_window = 0
    for key in order:
        v = groups[key]["v"]
        count = groups[key]["count"]
        d = _parse_date(v.get("insp_date", ""))
        # government data embeds soft hyphens (­) in some category names
        basic = (v.get("basic_desc") or "Other").replace("­", "")
        sev = int(float(v.get("severity_weight", 0) or 0))
        oos = str(v.get("oos_indicator", "false")).lower() == "true"
        in_alert = basic_map.get(basic, basic) in alert_set
        rolloff = d + timedelta(days=730) if d else None
        days_left = (rolloff - now).days if rolloff else None
        if days_left is not None and days_left < 0:
            continue  # already outside the 24-month scoring window
        basic_severity[basic] = basic_severity.get(basic, 0) + sev
        total_in_window += count
        section = v.get("section_desc", "") or ""
        is_ticket_shaped = "State/Local Laws" in section or basic == "Unsafe Driving"

        if is_ticket_shaped:
            verdict, priority = "POSSIBLE CHALLENGE - if the citation was dismissed or amended", 1
            evidence = "Court disposition / citation outcome; ELD + dashcam for that day"
        elif count > 1:
            verdict, priority = "VERIFY - appears {}x on this date".format(count), 3
            evidence = "Confirm on the full inspection report whether one event was recorded more than once"
        elif oos:
            verdict, priority = "REVIEW - out-of-service item", 4
            evidence = "Inspection report accuracy check; repair invoices; photos"
        elif sev >= 7 and in_alert:
            verdict, priority = "REVIEW - high-severity item", 5
            evidence = "ELD logs, dashcam, maintenance records for that date"
        elif days_left is not None and days_left <= 90:
            verdict, priority = "AGES OFF SOON", 8
            evidence = "None needed - ages off on " + rolloff.strftime("%b %d, %Y")
        else:
            verdict, priority = "MONITOR", 9
            evidence = "-"

        findings.append({
            "date": d.strftime("%b %d, %Y") if d else v.get("insp_date", "?"),
            "sort_date": d or now,
            "basic": basic,
            "title": short_title(section, v.get("group_desc", "")),
            "desc": section or v.get("group_desc", ""),
            "code": v.get("viol_code", ""),
            "severity": sev,
            "oos": oos,
            "count": count,
            "in_alert": in_alert,
            "verdict": verdict,
            "priority": priority,
            "evidence": evidence,
            "rolloff": rolloff.strftime("%b %d, %Y") if rolloff else "?",
        })

    findings.sort(key=lambda f: (f["priority"], -f["severity"]))
    n_challenge = sum(1 for f in findings if f["priority"] <= 2)
    n_investigate = sum(1 for f in findings if f["priority"] in (3, 4, 5))
    alert_basic_names = [b for b in basic_severity
                         if basic_map.get(b, b) in alert_set]
    summary = {
        "total_viols": total_in_window,
        "n_records": len(findings),
        "n_challenge": n_challenge,
        "n_investigate": n_investigate,
        "top3": findings[:3],
        "n_inspections": len(insps),
        "basic_severity": basic_severity,
        "alert_basics": alert_basic_names,
        "consequences": {b: BASIC_CONSEQUENCE.get(b, "may affect how your carrier is screened")
                         for b in alert_basic_names},
    }
    return findings, summary
