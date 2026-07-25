"""DataQs lead tracker + automatic audit generator — single-file local web app.
PIN-gated; intended for personal use over LAN or a private tunnel (Tailscale)."""
import json
import os
import secrets
import sqlite3
from flask import (Flask, jsonify, redirect, render_template_string, request,
                   send_file, session)

import audit as audit_engine

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "leads.db")
PDF_DIR = os.path.join(HERE, "audits")
SECRET_FILE = os.path.join(HERE, "secret.json")
os.makedirs(PDF_DIR, exist_ok=True)

# first run: generate a PIN + cookie-signing key; change the PIN in secret.json
if not os.path.exists(SECRET_FILE):
    with open(SECRET_FILE, "w") as f:
        json.dump({"pin": secrets.randbelow(900000) + 100000,
                   "flask_key": secrets.token_hex(32)}, f)
with open(SECRET_FILE) as f:
    _sec = json.load(f)

app = Flask(__name__)
app.secret_key = _sec["flask_key"]

LOGIN_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>DataQs Tracker — sign in</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:Segoe UI,Arial,sans-serif;background:#f5f7fa;display:flex;align-items:center;
justify-content:center;height:100vh;margin:0}form{background:#fff;border:1px solid #dde4ec;border-radius:10px;
padding:30px 34px;text-align:center}input{font-size:20px;padding:8px;width:130px;text-align:center;
border:1px solid #c3ceda;border-radius:8px;letter-spacing:3px}button{display:block;margin:14px auto 0;
padding:8px 22px;font-size:14px;background:#1f3864;color:#fff;border:none;border-radius:8px}
.err{color:#b91c1c;font-size:12.5px;margin-top:8px}</style></head><body>
<form method="post"><h3>DataQs Tracker</h3><input name="pin" inputmode="numeric" autofocus placeholder="PIN">
<button>Enter</button>{% if err %}<div class="err">wrong PIN</div>{% endif %}</form></body></html>"""


@app.before_request
def gate():
    if request.endpoint in ("login", "static"):
        return None
    if not session.get("ok"):
        return redirect("/login")
    return None


_attempts = {}  # ip -> [count, first_attempt_ts]


@app.route("/login", methods=["GET", "POST"])
def login():
    import time
    ip = request.headers.get("CF-Connecting-IP", request.remote_addr)
    if request.method == "POST":
        cnt, t0 = _attempts.get(ip, [0, time.time()])
        if time.time() - t0 > 900:          # 15-min window resets
            cnt, t0 = 0, time.time()
        if cnt >= 5:
            return "Too many attempts - locked for 15 minutes.", 429
        if request.form.get("pin", "").strip() == str(_sec["pin"]):
            _attempts.pop(ip, None)
            session.permanent = True
            session["ok"] = True
            return redirect("/")
        _attempts[ip] = [cnt + 1, t0]
        return render_template_string(LOGIN_PAGE, err=True)
    return render_template_string(LOGIN_PAGE, err=False)


from datetime import timedelta
app.permanent_session_lifetime = timedelta(days=60)

STATUSES = ["New", "Researching", "Audit Built", "Called - No Answer", "Called - Spoke",
            "Audit Emailed", "In Conversation", "Paid Audit ($500)", "Customer",
            "Not Interested", "Bad Fit", "Invalid Phone"]
PRIORITIES = ["", "A - hot", "B - warm", "C - later"]
EDITABLE = {"status", "priority", "first_contact", "last_contact", "audit_sent", "outcome", "next_step", "notes"}

# ---------------------------------------------------------------- tracker page
PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>DataQs Lead Tracker</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:16px;background:#f5f7fa;color:#1a2733}
 h1{font-size:20px;margin:0 0 4px}
 .sub{color:#5b6b7a;font-size:12px;margin-bottom:12px}
 .cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
 .card{background:#fff;border:1px solid #dde4ec;border-radius:8px;padding:8px 14px;font-size:13px}
 .card b{display:block;font-size:18px}
 .bar{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap}
 input[type=text],select{padding:6px 8px;border:1px solid #c3ceda;border-radius:6px;font-size:13px}
 .wrap{overflow-x:auto;background:#fff;border:1px solid #dde4ec;border-radius:8px}
 table{border-collapse:collapse;width:100%;font-size:12.5px}
 th{background:#1f3864;color:#fff;padding:7px 8px;text-align:left;position:sticky;top:0;white-space:nowrap}
 td{border-bottom:1px solid #eef1f5;padding:5px 8px;vertical-align:top}
 tr:hover{background:#f0f6ff}
 td[contenteditable]{background:#fffbe6;min-width:90px}
 td[contenteditable]:focus{outline:2px solid #3b82f6;background:#fff}
 select.cell{width:100%;border:none;background:transparent;font-size:12.5px}
 a{color:#0563c1}
 .pill{display:inline-block;padding:1px 7px;border-radius:10px;background:#e8eef7;font-size:11px;white-space:nowrap}
 .abtn{background:#16a34a;color:#fff;padding:2px 9px;border-radius:6px;text-decoration:none;font-size:11.5px;white-space:nowrap}
 .saved{position:fixed;right:14px;bottom:14px;background:#16a34a;color:#fff;padding:6px 12px;border-radius:6px;
        font-size:13px;opacity:0;transition:opacity .3s}
</style></head><body>
<h1>DataQs Lead Tracker</h1>
<div class="sub">{{total}} small carriers with active BASIC alert flags &middot; FMCSA SMS snapshot June 26, 2026 &middot; yellow cells are editable &middot; <b>Audit</b> builds the personalized audit page + PDF automatically</div>
<div class="cards">
 <div class="card"><b id="c_new">-</b>New</div>
 <div class="card"><b id="c_work">-</b>Working</div>
 <div class="card"><b id="c_paid">-</b>Paid audits</div>
 <div class="card"><b id="c_cust">-</b>Customers</div>
 <div class="card"><b id="c_dead">-</b>Dead</div>
</div>
<div class="bar">
 <input type="text" id="q" placeholder="search company / city / DOT..." oninput="paint()">
 <select id="fstatus" onchange="paint()"><option value="">all statuses</option>
 {% for s in statuses %}<option>{{s}}</option>{% endfor %}</select>
 <select id="fstate" onchange="paint()"><option value="">all states</option>
 {% for s in states %}<option>{{s}}</option>{% endfor %}</select>
</div>
<div class="wrap"><table id="t">
<thead><tr>
 <th>DOT #</th><th>Company</th><th>City</th><th>ST</th><th>Phone</th><th>Trucks</th>
 <th>Alert BASICs</th><th>Insp.</th><th>SMS</th><th>Audit</th><th>Status</th><th>Priority</th>
 <th>First contact</th><th>Last contact</th><th>Audit sent</th><th>Outcome</th><th>Next step</th><th>Notes</th>
</tr></thead><tbody>
{% for r in rows %}
<tr data-id="{{r['id']}}" data-status="{{r['status']}}" data-state="{{r['state']}}"
    data-blob="{{ (r['company'] ~ ' ' ~ r['city'] ~ ' ' ~ r['dot_number'])|lower }}">
 <td>{{r['dot_number']}}</td>
 <td><b>{{r['company']}}</b>{% if r['dba'] %}<br><span class="pill">dba {{r['dba']}}</span>{% endif %}</td>
 <td>{{r['city']}}</td><td>{{r['state']}}</td><td>{{r['phone']}}</td><td>{{r['trucks']}}</td>
 <td>{% for b in r['alert_basics'].split('|') %}<span class="pill">{{b}}</span> {% endfor %}</td>
 <td>{{r['inspections']}}</td>
 <td><a href="{{r['sms_profile']}}" target="_blank">open</a></td>
 <td><a class="abtn" href="/audit/{{r['id']}}" target="_blank">audit</a></td>
 <td><select class="cell" onchange="save(this,'status')">
   {% for s in statuses %}<option {% if r['status']==s %}selected{% endif %}>{{s}}</option>{% endfor %}
 </select></td>
 <td><select class="cell" onchange="save(this,'priority')">
   {% for p in priorities %}<option {% if r['priority']==p %}selected{% endif %}>{{p}}</option>{% endfor %}
 </select></td>
 <td contenteditable onblur="save(this,'first_contact')">{{r['first_contact'] or ''}}</td>
 <td contenteditable onblur="save(this,'last_contact')">{{r['last_contact'] or ''}}</td>
 <td><select class="cell" onchange="save(this,'audit_sent')">
   <option></option><option {% if r['audit_sent']=='Yes' %}selected{% endif %}>Yes</option>
   <option {% if r['audit_sent']=='No' %}selected{% endif %}>No</option>
 </select></td>
 <td contenteditable onblur="save(this,'outcome')">{{r['outcome'] or ''}}</td>
 <td contenteditable onblur="save(this,'next_step')">{{r['next_step'] or ''}}</td>
 <td contenteditable onblur="save(this,'notes')" style="min-width:180px">{{r['notes'] or ''}}</td>
</tr>
{% endfor %}
</tbody></table></div>
<div class="saved" id="saved">saved ✓</div>
<script>
const DEAD = ["Not Interested","Bad Fit","Invalid Phone"];
function save(el, field){
  const tr = el.closest('tr');
  const val = el.tagName === 'SELECT' ? el.value : el.innerText.trim();
  if(field === 'status') tr.dataset.status = val;
  fetch('/update', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({id: tr.dataset.id, field: field, value: val})})
    .then(r => { if(r.ok){ const s=document.getElementById('saved'); s.style.opacity=1;
                 setTimeout(()=>s.style.opacity=0, 900); counts(); }});
}
function paint(){
  const q = document.getElementById('q').value.toLowerCase();
  const fs = document.getElementById('fstatus').value;
  const fst = document.getElementById('fstate').value;
  document.querySelectorAll('#t tbody tr').forEach(tr => {
    const ok = (!q || tr.dataset.blob.includes(q)) &&
               (!fs || tr.dataset.status === fs) &&
               (!fst || tr.dataset.state === fst);
    tr.style.display = ok ? '' : 'none';
  });
}
function counts(){
  let n=0, w=0, p=0, c=0, d=0;
  document.querySelectorAll('#t tbody tr').forEach(tr => {
    const s = tr.dataset.status;
    if(s === 'New') n++;
    else if(s === 'Paid Audit ($500)') p++;
    else if(s === 'Customer') c++;
    else if(DEAD.includes(s)) d++;
    else w++;
  });
  c_new.textContent=n; c_work.textContent=w; c_paid.textContent=p; c_cust.textContent=c; c_dead.textContent=d;
}
counts();
</script></body></html>"""

# ---------------------------------------------------------------- audit page
AUDIT_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>CSA Record Audit — {{lead['company']}}</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#eef1f5;color:#1a2733}
 .sheet{max-width:860px;margin:24px auto;background:#fff;border:1px solid #d8dfe8;border-radius:10px;padding:34px 40px}
 h1{font-size:24px;margin:0}
 h2{font-size:16px;margin:26px 0 8px;color:#1f3864}
 .meta{color:#5b6b7a;font-size:12.5px;margin:6px 0 18px}
 .alertbox{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px 16px;font-size:14px;margin-bottom:6px}
 .statrow{display:flex;gap:12px;margin:14px 0}
 .stat{flex:1;background:#f6f8fb;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;text-align:center}
 .stat b{display:block;font-size:22px}
 .stat span{font-size:11.5px;color:#5b6b7a}
 table{border-collapse:collapse;width:100%;font-size:12.5px;margin-top:8px}
 th{background:#1f3864;color:#fff;padding:6px 8px;text-align:left}
 td{border-bottom:1px solid #eef1f5;padding:6px 8px;vertical-align:top}
 .v1{background:#dcfce7;color:#14532d;font-weight:600;padding:1px 7px;border-radius:9px;font-size:11px;white-space:nowrap}
 .v2{background:#fef9c3;color:#713f12;font-weight:600;padding:1px 7px;border-radius:9px;font-size:11px;white-space:nowrap}
 .v3{background:#e8eef7;color:#334155;padding:1px 7px;border-radius:9px;font-size:11px;white-space:nowrap}
 .cta{background:#1f3864;color:#fff;border-radius:10px;padding:20px 24px;margin-top:26px}
 .cta h2{color:#fff;margin-top:0}
 .cta .price{font-size:20px;font-weight:700}
 .guarantee{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:10px 14px;font-size:12.5px;margin-top:10px;color:#14532d}
 .fine{color:#8494a5;font-size:10.5px;margin-top:22px;line-height:1.5}
 .btnrow{margin:18px 0 0;display:flex;gap:10px}
 .btn{background:#16a34a;color:#fff;padding:8px 16px;border-radius:8px;text-decoration:none;font-size:13.5px}
 .btn2{background:#e8eef7;color:#1f3864;padding:8px 16px;border-radius:8px;text-decoration:none;font-size:13.5px}
 @media print {.btnrow{display:none} body{background:#fff} .sheet{border:none;margin:0}}
</style></head><body><div class="sheet">
<h1>CSA Record Error Audit</h1>
<div class="meta"><b>{{lead['company']}}</b> &middot; DOT # {{lead['dot_number']}} &middot; {{lead['city']}}, {{lead['state']}} &middot;
prepared {{fetched}} from public FMCSA data</div>

{% for b in summary['alert_basics'] %}
<div class="alertbox">⚠ Your record currently carries an <b>active federal alert flag in {{b}}</b> —
{{summary['consequences'][b]}}.</div>
{% endfor %}

<div class="statrow">
 <div class="stat"><b>{{summary['total_viols']}}</b><span>violations still in your 24-month scoring window</span></div>
 <div class="stat"><b>{{summary['n_challenge']}}</b><span>look challengeable right now</span></div>
 <div class="stat"><b>{{summary['n_investigate']}}</b><span>worth investigating with your records</span></div>
 <div class="stat"><b>{{summary['n_inspections']}}</b><span>inspections on file</span></div>
</div>

<p style="font-size:14px">Every violation below is still counting against your CSA scores. Carriers with elevated
scores lose an estimated 20&ndash;40% of available freight opportunities, pay more at every insurance renewal, and get
inspected more often. Some of these records may not belong on your file &mdash; but under the new DataQs rules
(April 2026), <b>they only come off if someone challenges them with the right evidence, before they do their damage.</b></p>

<h2>What we found on your record</h2>
<table>
<tr><th>Date</th><th>Violation</th><th>BASIC</th><th>Sev.</th><th>Our read</th><th>Evidence needed</th><th>Rolls off</th></tr>
{% for f in findings %}
<tr>
 <td style="white-space:nowrap">{{f['date']}}</td>
 <td>{{f['desc']}}{% if f['oos'] %} <b>(OOS)</b>{% endif %}</td>
 <td>{{f['basic']}}</td>
 <td>{{f['severity']}}</td>
 <td>{% if f['priority'] <= 2 %}<span class="v1">{{f['verdict']}}</span>
     {% elif f['priority'] <= 4 %}<span class="v2">{{f['verdict']}}</span>
     {% else %}<span class="v3">{{f['verdict']}}</span>{% endif %}</td>
 <td>{{f['evidence']}}</td>
 <td style="white-space:nowrap">{{f['rolloff']}}</td>
</tr>
{% endfor %}
</table>

<div class="cta">
<h2>What we'd do next — the Founding Carrier Record Rescue</h2>
<p>We audit your full 24-month record against your own evidence (ELD, dashcam, tickets, court outcomes), build the
strongest supportable DataQs challenge for every flagged record above, file it, and chase every deadline of the new
21-day review process until you have a written answer.</p>
<div class="price">$500 flat — full audit + your first challenge package</div>
<div style="font-size:12.5px;margin-top:4px">Founding price, limited to our first 10 carriers. Then continuous monitoring from $149/mo — we watch your record and preserve evidence before it disappears.</div>
<div class="guarantee"><b>Perfect Package Guarantee:</b> every challenge we submit includes the required factual/legal basis,
your supporting documentation, and deadline tracking. If we miss a filing deadline or omit evidence you provided on time,
that case is free and the next eligible one is on us.</div>
<div style="margin-top:12px;font-size:13.5px">📞 [YOUR PHONE] &nbsp;&middot;&nbsp; ✉ [YOUR EMAIL]</div>
</div>

<div class="btnrow">
 <a class="btn" href="/audit/{{lead['id']}}/pdf">Download PDF (to attach)</a>
 <a class="btn2" href="/audit/{{lead['id']}}?refresh=1">Refresh data</a>
 <a class="btn2" href="/">← back to tracker</a>
</div>

<div class="fine">Prepared from public FMCSA SMS/MCMIS data. This document identifies records that may merit a DataQs
Request for Data Review; it is not legal advice, and correction decisions are made solely by FMCSA and state reviewing
agencies. "Challengeable" reflects our reading of the public record only — supporting evidence from your files determines
what is actually filed. Freight-opportunity estimate: industry analyses of broker carrier-screening practices.</div>
</div></body></html>"""


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


@app.route("/")
def index():
    con = db()
    rows = con.execute(
        "SELECT * FROM leads ORDER BY n_alerts DESC, inspections DESC").fetchall()
    states = [r[0] for r in con.execute(
        "SELECT DISTINCT state FROM leads WHERE state != '' ORDER BY state")]
    con.close()
    return render_template_string(PAGE, rows=rows, total=len(rows),
                                  statuses=STATUSES, priorities=PRIORITIES, states=states)


@app.route("/update", methods=["POST"])
def update():
    d = request.get_json(force=True)
    field = d.get("field")
    if field not in EDITABLE:
        return jsonify(error="field not editable"), 400
    con = db()
    con.execute("UPDATE leads SET {} = ? WHERE id = ?".format(field), (d.get("value", ""), d["id"]))
    con.commit()
    con.close()
    return jsonify(ok=True)


def _build_audit(lead_id, refresh=False):
    con = db()
    lead = con.execute("SELECT * FROM leads WHERE id=?", (lead_id,)).fetchone()
    if lead is None:
        con.close()
        return None, None, None, None
    if refresh:
        con.execute("DELETE FROM audit_cache WHERE dot_number=?", (lead["dot_number"],))
        con.commit()
    viols, insps, fetched = audit_engine.fetch_history(lead["dot_number"], con)
    findings, summary = audit_engine.analyze(viols, insps, lead["alert_basics"])
    if lead["status"] == "New":
        con.execute("UPDATE leads SET status='Audit Built' WHERE id=?", (lead_id,))
        con.commit()
    con.close()
    return lead, findings, summary, fetched


@app.route("/audit/<int:lead_id>")
def audit_page(lead_id):
    lead, findings, summary, fetched = _build_audit(
        lead_id, refresh=request.args.get("refresh") == "1")
    if lead is None:
        return "lead not found", 404
    return render_template_string(AUDIT_PAGE, lead=lead, findings=findings,
                                  summary=summary, fetched=fetched)


@app.route("/audit/<int:lead_id>/pdf")
def audit_pdf(lead_id):
    lead, findings, summary, fetched = _build_audit(lead_id)
    if lead is None:
        return "lead not found", 404
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)

    path = os.path.join(PDF_DIR, "audit_{}_{}.pdf".format(lead["dot_number"], lead_id))
    doc = SimpleDocTemplate(path, pagesize=letter, leftMargin=0.7 * inch,
                            rightMargin=0.7 * inch, topMargin=0.6 * inch,
                            bottomMargin=0.6 * inch)
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontName="Helvetica-Bold",
                        fontSize=18, spaceAfter=2, alignment=0)
    meta = ParagraphStyle("meta", parent=ss["Normal"], fontSize=9, textColor=colors.HexColor("#5b6b7a"))
    body = ParagraphStyle("body", parent=ss["Normal"], fontSize=10.5, leading=14)
    warn = ParagraphStyle("warn", parent=body, textColor=colors.HexColor("#991b1b"))
    small = ParagraphStyle("small", parent=ss["Normal"], fontSize=7.5,
                           textColor=colors.HexColor("#8494a5"), leading=9.5)
    cell = ParagraphStyle("cell", parent=ss["Normal"], fontSize=8, leading=10)
    cellb = ParagraphStyle("cellb", parent=cell, fontName="Helvetica-Bold")

    el = []
    el.append(Paragraph("CSA Record Error Audit", h1))
    el.append(Paragraph("{} — DOT # {} — {}, {} — prepared {} from public FMCSA data".format(
        lead["company"], lead["dot_number"], lead["city"], lead["state"], fetched), meta))
    el.append(Spacer(1, 10))
    for b in summary["alert_basics"]:
        el.append(Paragraph("⚠ ACTIVE FEDERAL ALERT FLAG: <b>{}</b> — {}.".format(
            b, summary["consequences"][b]), warn))
    el.append(Spacer(1, 8))
    el.append(Paragraph(
        "<b>{}</b> violations remain in your 24-month scoring window. <b>{}</b> look challengeable right now and "
        "<b>{}</b> are worth investigating against your own records. Elevated CSA scores cost carriers an estimated "
        "20&ndash;40% of available freight opportunities plus higher insurance at every renewal. Under the April 2026 "
        "DataQs rules these records only come off if someone challenges them with the right evidence.".format(
            summary["total_viols"], summary["n_challenge"], summary["n_investigate"]), body))
    el.append(Spacer(1, 12))

    rows = [["Date", "Violation", "BASIC", "Sev.", "Our read", "Evidence needed"]]
    for f in findings[:28]:
        rows.append([Paragraph(f["date"], cell),
                     Paragraph(f["desc"] + (" (OOS)" if f["oos"] else ""), cell),
                     Paragraph(f["basic"], cell),
                     str(f["severity"]),
                     Paragraph(f["verdict"], cellb),
                     Paragraph(f["evidence"], cell)])
    t = Table(rows, colWidths=[0.75 * inch, 2.1 * inch, 1.0 * inch, 0.4 * inch, 1.35 * inch, 1.6 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3864")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, 0), 8.5),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d8dfe8")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fb")]),
    ]))
    el.append(t)
    if len(findings) > 28:
        el.append(Paragraph("...plus {} more records — full list reviewed in your paid audit.".format(
            len(findings) - 28), meta))
    el.append(Spacer(1, 14))
    el.append(Paragraph("<b>Next step — Founding Carrier Record Rescue ($500 flat):</b> full 24-month audit against "
                        "your own evidence (ELD, dashcam, tickets, court outcomes), plus your first complete DataQs "
                        "challenge package, filed and chased through every deadline of the 21-day review until you have "
                        "a written answer. Founding price, first 10 carriers only. Then continuous monitoring from "
                        "$149/mo. <b>Perfect Package Guarantee:</b> if we miss a filing deadline or omit evidence you "
                        "provided on time, that case is free and the next eligible one is on us.", body))
    el.append(Spacer(1, 6))
    el.append(Paragraph("Call: [YOUR PHONE] — Email: [YOUR EMAIL]", body))
    el.append(Spacer(1, 12))
    el.append(Paragraph("Prepared from public FMCSA SMS/MCMIS data. Identifies records that may merit a DataQs Request "
                        "for Data Review; not legal advice. Correction decisions are made solely by FMCSA and state "
                        "reviewing agencies. 'Challengeable' reflects our reading of the public record; your evidence "
                        "determines what is actually filed.", small))
    doc.build(el)
    return send_file(path, as_attachment=True,
                     download_name="CSA_Record_Audit_{}.pdf".format(lead["company"].replace(" ", "_")))


if __name__ == "__main__":
    # 0.0.0.0 = reachable from other devices on your local network (phone on
    # same Wi-Fi). No auth exists yet — do NOT expose this to the public
    # internet; for remote access use a private tunnel (e.g. Tailscale).
    app.run(host="0.0.0.0", port=8765, debug=False)
