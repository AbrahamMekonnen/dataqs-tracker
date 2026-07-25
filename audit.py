"""Audit engine: pulls a carrier's public FMCSA inspection/violation history,
applies challengeability rules, and returns structured findings for rendering."""
import json
import sqlite3
from datetime import datetime, timedelta

import requests

VIOL_URL = "https://data.transportation.gov/resource/8mt8-2mdr.json"
INSP_URL = "https://data.transportation.gov/resource/rbkj-cgst.json"

BASIC_CONSEQUENCE = {
    "Unsafe Driving": "the #1 score brokers screen on before tendering loads",
    "HOS Compliance": "a top trigger for focused roadside inspections",
    "Driver Fitness": "a common reason insurers re-rate premiums upward",
    "Controlled Substances/Alcohol": "an immediate red flag for shippers and insurers",
    "Vehicle Maintenance": "the most common alert - and the most fixable on paper",
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


def analyze(viols, insps, alert_basics):
    """Rule-based challengeability analysis. Returns findings + summary."""
    now = datetime.now()
    alert_set = set((alert_basics or "").split("|"))
    # map SMS file's basic names to lead-list alert names
    basic_map = {"Unsafe Driving": "UnsafeDriving", "HOS Compliance": "HOS",
                 "Driver Fitness": "DriverFitness",
                 "Controlled Substances/Alcohol": "DrugsAlcohol",
                 "Vehicle Maintenance": "VehicleMaint"}

    # detect possible duplicates: same code + same date + same unit (tractor vs
    # trailer can legitimately share a code on one inspection, so unit matters)
    seen = {}
    for v in viols:
        key = (v.get("viol_code"), v.get("insp_date"), v.get("viol_unit"))
        seen[key] = seen.get(key, 0) + 1

    findings = []
    basic_severity = {}
    for v in viols:
        d = _parse_date(v.get("insp_date", ""))
        basic = v.get("basic_desc", "Other")
        sev = int(float(v.get("severity_weight", 0) or 0))
        oos = str(v.get("oos_indicator", "false")).lower() == "true"
        in_alert = basic_map.get(basic, basic) in alert_set
        basic_severity[basic] = basic_severity.get(basic, 0) + sev
        rolloff = d + timedelta(days=730) if d else None
        days_left = (rolloff - now).days if rolloff else None
        if days_left is not None and days_left < 0:
            continue  # already outside the 24-month scoring window

        key = (v.get("viol_code"), v.get("insp_date"), v.get("viol_unit"))
        is_dup = seen.get(key, 0) > 1
        section = v.get("section_desc", "") or ""
        is_ticket_shaped = "State/Local Laws" in section or basic == "Unsafe Driving"

        if is_dup:
            verdict, priority = "VERIFY - possible duplicate entry", 1
            evidence = "Pull the inspection report: if one event was recorded twice, challenge as duplicate"
        elif is_ticket_shaped:
            verdict, priority = "CHALLENGE IF TICKET WAS DISMISSED", 2
            evidence = "Court disposition / citation outcome; ELD + dashcam for the day"
        elif oos:
            verdict, priority = "INVESTIGATE - out-of-service violation", 3
            evidence = "Inspection report accuracy check; repair invoices; photos"
        elif sev >= 7 and in_alert:
            verdict, priority = "INVESTIGATE - high severity in alert BASIC", 4
            evidence = "ELD logs, dashcam, maintenance records for that date"
        elif days_left is not None and days_left <= 90:
            verdict, priority = "LEAVE ALONE - rolls off soon", 8
            evidence = "None needed - ages out on " + rolloff.strftime("%b %d, %Y")
        else:
            verdict, priority = "MONITOR", 9
            evidence = "-"

        findings.append({
            "date": d.strftime("%b %d, %Y") if d else v.get("insp_date", "?"),
            "sort_date": d or now,
            "basic": basic,
            "desc": section or v.get("group_desc", ""),
            "code": v.get("viol_code", ""),
            "severity": sev,
            "oos": oos,
            "in_alert": in_alert,
            "verdict": verdict,
            "priority": priority,
            "evidence": evidence,
            "rolloff": rolloff.strftime("%b %d, %Y") if rolloff else "?",
        })

    findings.sort(key=lambda f: (f["priority"], -f["severity"]))
    n_challenge = sum(1 for f in findings if f["priority"] <= 2)
    n_investigate = sum(1 for f in findings if f["priority"] in (3, 4))
    alert_basic_names = [b for b in basic_severity
                         if basic_map.get(b, b) in alert_set]
    summary = {
        "total_viols": len(findings),
        "n_challenge": n_challenge,
        "n_investigate": n_investigate,
        "n_inspections": len(insps),
        "basic_severity": basic_severity,
        "alert_basics": alert_basic_names,
        "consequences": {b: BASIC_CONSEQUENCE.get(b, "affects your CSA percentile")
                         for b in alert_basic_names},
    }
    return findings, summary
