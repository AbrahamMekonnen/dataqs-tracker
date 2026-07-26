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
    "Vehicle Maintenance": "some items may be verified using inspection reports, maintenance records, and dated photos",
}


def classify_kind(section, group):
    """One classifier used for BOTH the verdict and the evidence, so they never
    disagree. 'moving' is checked first because traffic-control descriptions
    literally contain the word 'light' ('signal sign light'), which must not be
    mistaken for an equipment-lighting defect."""
    s = (section or group or "").lower()
    if any(k in s for k in ("speeding", "seat belt", "traffic control", "lane restriction",
                            "follow", "move over", "stop sign", "yield", "improper turn",
                            "reckless", "texting", "hand-held", "hand held", "failure to obey")):
        return "moving"
    if "medical" in s:
        return "medical"
    if any(k in s for k in ("drug", "alcohol", "controlled subst")):
        return "drugs"
    if any(k in s for k in ("cdl", "license", "restriction", "endorsement")) or "operate a cmv" in s:
        return "license"
    if any(k in s for k in ("record of duty", "rods", "hours of service", "duty status", "logbook")):
        return "hos"
    if any(k in s for k in ("placard", "hazmat", "hazardous", "shipping paper")):
        return "hazmat"
    if any(k in s for k in ("brake", "tire", "lamp", "lighting", "suspension", "cargo", "wheel", "mud",
                            "flap", "steering", "fire extinguish", "emergency equipment", "coupling",
                            "frame", "windshield", "wiper", "horn", "mirror", "exhaust", "fuel", "leak",
                            "hose", "load secure")):
        return "equipment"
    return "other"


_EVIDENCE_BY_KIND = {
    "moving": "Court disposition or citation outcome; ELD logs and dashcam for that day; the inspection report",
    "medical": ("Full inspection report; valid medical certificate and examiner documentation for that date; "
                "state self-certification record"),
    "drugs": "Full inspection report; documentation and context of the finding; any related test or court records",
    "license": ("Full inspection report; copy of the CDL showing class/endorsements/restrictions; state "
                "motor-vehicle record showing valid status on the inspection date"),
    "hos": "ELD logs and supporting duty records for that period; the inspection report",
    "hazmat": "Full inspection report; dated photos of placarding; shipping papers for the load",
    "equipment": ("Full inspection report; maintenance/repair records and dated photos of the item; driver "
                  "inspection records from that date, if available"),
    "other": "Full inspection report; documentation from your files showing the record is inaccurate",
}


def evidence_for(section, group, is_dup):
    if is_dup:
        return "Full inspection report — confirm whether one event was recorded more than once"
    return _EVIDENCE_BY_KIND[classify_kind(section, group)]


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
        kind = classify_kind(section, v.get("group_desc", ""))

        if count > 1:
            verdict, priority = "VERIFY - appears {}x on this date".format(count), 3
        elif kind == "moving":
            verdict, priority = "POSSIBLE CHALLENGE - if the citation was dismissed or amended", 1
        elif oos:
            verdict, priority = "REVIEW - out-of-service item", 4
        elif sev >= 7 and in_alert:
            verdict, priority = "REVIEW - high-severity item", 5
        elif days_left is not None and days_left <= 90:
            verdict, priority = "AGES OFF SOON", 8
        else:
            verdict, priority = "MONITOR", 9

        if priority == 8:
            evidence = "None needed - ages off on " + rolloff.strftime("%b %d, %Y")
        elif priority == 9:
            evidence = "-"
        else:
            evidence = evidence_for(section, v.get("group_desc", ""), count > 1)

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

    # diversify the top 3 so it showcases the DIFFERENT ways we find value
    # (a possible challenge, a possible duplicate, a record-accuracy review) —
    # not three near-identical speeding rows
    top3 = []
    used = set()
    for cond in (lambda f: f["priority"] <= 2,       # possible challenge
                 lambda f: f["priority"] == 3,       # possible duplicate
                 lambda f: f["priority"] in (4, 5)):  # OOS / accuracy review
        for i, f in enumerate(findings):
            if i not in used and cond(f):
                top3.append(f)
                used.add(i)
                break
    for i, f in enumerate(findings):  # fill remaining slots by priority
        if len(top3) >= 3:
            break
        if i not in used:
            top3.append(f)
            used.add(i)
    alert_basic_names = [b for b in basic_severity
                         if basic_map.get(b, b) in alert_set]
    summary = {
        "total_viols": total_in_window,
        "n_records": len(findings),
        "n_challenge": n_challenge,
        "n_investigate": n_investigate,
        "top3": top3,
        "n_inspections": len(insps),
        "basic_severity": basic_severity,
        "alert_basics": alert_basic_names,
        "consequences": {b: BASIC_CONSEQUENCE.get(b, "may affect how your carrier is screened")
                         for b in alert_basic_names},
    }
    return findings, summary
