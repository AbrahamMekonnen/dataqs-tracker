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
# DATA_DIR: on Railway this points at the mounted volume (/data) so the
# database, PIN, and generated PDFs survive redeploys; locally it's the app dir.
DATA = os.environ.get("DATA_DIR", HERE)
os.makedirs(DATA, exist_ok=True)
DB = os.path.join(DATA, "leads.db")
PDF_DIR = os.path.join(DATA, "audits")
SECRET_FILE = os.path.join(DATA, "secret.json")
os.makedirs(PDF_DIR, exist_ok=True)

# first boot on a fresh volume: seed the database from the bundled CSV
if not os.path.exists(DB):
    import seed_db  # noqa: F401  (runs the seed as an import side effect)

# light migration: add the email column to older databases
_c = sqlite3.connect(DB)
try:
    _c.execute("ALTER TABLE leads ADD COLUMN email TEXT")
    _c.commit()
except sqlite3.OperationalError:
    pass
_c.close()

# email sending config: fill in the blanks in email_config.json (or set the
# same keys as environment variables on the cloud host). For Gmail: enable
# 2-step verification, then create an App Password at
# https://myaccount.google.com/apppasswords and paste it as smtp_pass.
EMAIL_CFG_FILE = os.path.join(DATA, "email_config.json")
if not os.path.exists(EMAIL_CFG_FILE):
    with open(EMAIL_CFG_FILE, "w") as f:
        json.dump({"smtp_host": "smtp.gmail.com", "smtp_port": 587,
                   "smtp_user": "", "smtp_pass": "", "api_key": "",
                   "from_name": "", "my_name": "", "my_phone": ""}, f, indent=2)


def email_cfg():
    with open(EMAIL_CFG_FILE) as f:
        cfg = json.load(f)
    for k in list(cfg):
        if os.environ.get(k.upper()):
            cfg[k] = os.environ[k.upper()]
    # accept common aliases for the email-API key
    cfg["api_key"] = (os.environ.get("BREVO_API_KEY") or os.environ.get("EMAIL_API_KEY")
                      or cfg.get("api_key", ""))
    return cfg


RECOMMENDED_TEMPLATE = """Subject: Your CSA Record Audit - [COMPANY]

Hi,

As promised, here's the CSA Record Error Audit I put together for [COMPANY] (USDOT [DOT]) from the public federal inspection record.

A few things it flags:
- [TOTAL] violations are still inside your 24-month scoring window
- [CHALLENGE] look potentially challengeable, depending on the documents you have
- your record currently shows alert flags in [ALERTS]

The attached PDF lists the specific records and what evidence each one would need for a DataQs challenge. Nothing here is a guarantee - FMCSA and the states make the final call - but these are the items I'd look at first.

If you'd like me to run them down for you, the Founding Carrier Record Rescue is $500 flat: I review all 24 months, build your first challenge, file it, and track it through the 21-day review until you get a written answer. Founding price for my first 10 carriers.

Either way, happy to answer any questions.

[MY_NAME]
CSA Record Rescue
CSA record reviews and DataQs filing support
[MY_PHONE]
Independent service - not affiliated with FMCSA or any state agency
"""

TEMPLATE_FILE = os.path.join(DATA, "email_template.txt")
if not os.path.exists(TEMPLATE_FILE):
    with open(TEMPLATE_FILE, "w", encoding="utf-8") as f:
        f.write(RECOMMENDED_TEMPLATE)

# first run: generate a PIN + cookie-signing key; change the PIN in secret.json
if not os.path.exists(SECRET_FILE):
    with open(SECRET_FILE, "w") as f:
        json.dump({"pin": secrets.randbelow(900000) + 100000,
                   "flask_key": secrets.token_hex(32)}, f)
with open(SECRET_FILE) as f:
    _sec = json.load(f)
# cloud override: set APP_PIN in the host's environment variables to choose
# your own PIN (Railway dashboard -> service -> Variables)
if os.environ.get("APP_PIN"):
    _sec["pin"] = os.environ["APP_PIN"].strip()
    print("[startup] PIN source: APP_PIN environment variable", flush=True)
else:
    print("[startup] PIN source: generated secret.json (APP_PIN env var NOT set "
          "- on Railway, add APP_PIN in the service's Variables tab)", flush=True)

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
EDITABLE = {"status", "priority", "first_contact", "last_contact", "audit_sent", "outcome", "next_step", "notes", "email"}

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
<div class="sub">{{total}} small carriers with active BASIC alert flags &middot; FMCSA SMS snapshot June 26, 2026 &middot; yellow cells are editable &middot; <b>Audit</b> builds the personalized audit page + PDF automatically &middot; <a href="/template">edit email template</a></div>
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
 <th>Alert BASICs</th><th>Insp.</th><th>SMS</th><th>Audit</th><th>Email</th><th>✉</th><th>Status</th><th>Priority</th>
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
 <td><a class="abtn" href="/audit/{{r['id']}}/{{r['slug']}}" target="_blank">audit</a></td>
 <td contenteditable onblur="save(this,'email')" class="mail" style="min-width:150px">{{r['email'] or ''}}</td>
 <td><a class="abtn sendbtn" href="#" onclick="return sendAudit(this)">send</a></td>
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
function sendAudit(el){
  const tr = el.closest('tr');
  const email = tr.querySelector('td.mail').innerText.trim();
  if(!email || !email.includes('@')){ alert('Type their email in the Email cell first.'); return false; }
  const company = tr.querySelector('td b').innerText;
  if(!confirm('Send audit PDF + pitch email to ' + email + ' (' + company + ')?')) return false;
  el.textContent = '...';
  fetch('/send/' + tr.dataset.id, {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({email: email})})
    .then(r => r.json().then(j => ({ok: r.ok, j: j})))
    .then(({ok, j}) => {
      if(ok){
        el.textContent = 'sent ✓'; el.style.background = '#6b7280';
        tr.dataset.status = 'Audit Emailed';
        const sel = tr.querySelectorAll('select.cell');
        sel[0].value = 'Audit Emailed';          // status dropdown
        sel[2].value = 'Yes';                    // audit-sent dropdown
        counts();
      } else {
        el.textContent = 'send';
        alert(j.error || 'send failed');
      }
    })
    .catch(e => { el.textContent = 'send'; alert('send failed: ' + e); });
  return false;
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
 <a class="btn" href="/audit/{{lead['id']}}/{{slug}}/pdf">Download PDF (to attach)</a>
 <a class="btn2" href="/audit/{{lead['id']}}/{{slug}}?refresh=1">Refresh data</a>
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


def slugify(s):
    import re
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-") or "carrier"


@app.route("/")
def index():
    con = db()
    rows = [dict(r) for r in con.execute(
        "SELECT * FROM leads ORDER BY n_alerts DESC, inspections DESC")]
    for r in rows:
        r["slug"] = slugify(r["company"])
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
@app.route("/audit/<int:lead_id>/<slug>")
def audit_page(lead_id, slug=None):
    lead, findings, summary, fetched = _build_audit(
        lead_id, refresh=request.args.get("refresh") == "1")
    if lead is None:
        return "lead not found", 404
    want = slugify(lead["company"])
    if slug != want:  # keep URLs canonical and readable
        return redirect("/audit/{}/{}".format(lead_id, want))
    return render_template_string(AUDIT_PAGE, lead=lead, findings=findings,
                                  summary=summary, fetched=fetched, slug=want)


@app.route("/audit/<int:lead_id>/pdf")
@app.route("/audit/<int:lead_id>/<slug>/pdf")
def audit_pdf(lead_id, slug=None):
    lead, findings, summary, fetched = _build_audit(lead_id)
    if lead is None:
        return "lead not found", 404
    path = _render_pdf(lead, findings, summary, fetched)
    return send_file(path, as_attachment=True, download_name=pdf_filename(lead))


def pdf_filename(lead):
    # boring/credible filename per Hormozi: DOT-<num>-CSA-Record-Review.pdf
    return "DOT-{}-CSA-Record-Review.pdf".format(lead["dot_number"])


def _render_pdf(lead, findings, summary, fetched):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)

    path = os.path.join(PDF_DIR, "audit_{}_{}.pdf".format(lead["dot_number"], lead["id"]))
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

    h2 = ParagraphStyle("h2", parent=ss["Normal"], fontName="Helvetica-Bold",
                        fontSize=13, textColor=colors.HexColor("#1f3864"),
                        spaceBefore=6, spaceAfter=6)
    statnum = ParagraphStyle("statnum", parent=ss["Normal"], fontName="Helvetica-Bold",
                             fontSize=17, alignment=1)
    statlbl = ParagraphStyle("statlbl", parent=ss["Normal"], fontSize=7.5,
                             textColor=colors.HexColor("#5b6b7a"), alignment=1, leading=9)

    def short_basic(b):
        # source data can contain soft hyphens/odd chars — match by substring
        lb = (b or "").lower()
        if "controlled" in lb or "alcohol" in lb:
            return "Drugs / Alcohol"
        if "hours" in lb or "hos" in lb:
            return "HOS Compliance"
        if "maintenance" in lb:
            return "Vehicle Maint."
        return "".join(ch for ch in b if ord(ch) < 0x2000)

    el = []
    el.append(Paragraph("CSA Record Error Audit", h1))
    el.append(Paragraph("{} — DOT # {} — {}, {} — prepared {} from public FMCSA data".format(
        lead["company"], lead["dot_number"], lead["city"], lead["state"], fetched), meta))
    el.append(Spacer(1, 10))
    for b in summary["alert_basics"]:
        wt = Table([[Paragraph("<b>ACTIVE FEDERAL ALERT FLAG — {}:</b> {}.".format(
            b, summary["consequences"][b]), warn)]], colWidths=[7.2 * inch])
        wt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
            ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#fecaca")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        el.append(wt)
        el.append(Spacer(1, 4))
    el.append(Spacer(1, 6))

    stats = Table([[
        Paragraph(str(summary["total_viols"]), statnum),
        Paragraph(str(summary["n_challenge"]), statnum),
        Paragraph(str(summary["n_investigate"]), statnum),
        Paragraph(str(summary["n_inspections"]), statnum)],
        [Paragraph("violations in your<br/>24-month window", statlbl),
         Paragraph("look challengeable<br/>right now", statlbl),
         Paragraph("worth investigating<br/>with your records", statlbl),
         Paragraph("inspections<br/>on file", statlbl)]],
        colWidths=[1.8 * inch] * 4)
    stats.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f6f8fb")),
        ("BOX", (0, 0), (0, -1), 0.7, colors.HexColor("#e2e8f0")),
        ("BOX", (1, 0), (1, -1), 0.7, colors.HexColor("#e2e8f0")),
        ("BOX", (2, 0), (2, -1), 0.7, colors.HexColor("#e2e8f0")),
        ("BOX", (3, 0), (3, -1), 0.7, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, 0), 7), ("BOTTOMPADDING", (0, 1), (-1, 1), 7),
    ]))
    el.append(stats)
    el.append(Spacer(1, 10))

    el.append(Paragraph(
        "Every violation below is still counting against your CSA scores. Carriers with elevated scores lose an "
        "estimated 20&ndash;40% of available freight opportunities, pay more at every insurance renewal, and get "
        "inspected more often. Under the April 2026 DataQs rules, wrong records only come off if someone challenges "
        "them with the right evidence &mdash; before they do their damage.", body))
    el.append(Spacer(1, 10))
    el.append(Paragraph("What we found on your record", h2))

    rows = [["Date", "Violation", "BASIC", "Sev.", "Our read", "Evidence needed"]]
    vstyles = []
    for i, f in enumerate(findings[:28], 1):
        if f["priority"] <= 2:
            bg, fg = "#dcfce7", "#14532d"
        elif f["priority"] <= 4:
            bg, fg = "#fef9c3", "#713f12"
        else:
            bg, fg = "#eef1f5", "#334155"
        vstyles.append(("BACKGROUND", (4, i), (4, i), colors.HexColor(bg)))
        vstyles.append(("TEXTCOLOR", (4, i), (4, i), colors.HexColor(fg)))
        vcell = ParagraphStyle("v{}".format(i), parent=cellb, textColor=colors.HexColor(fg))
        rows.append([Paragraph(f["date"], cell),
                     Paragraph(f["desc"] + (" <b>(OOS)</b>" if f["oos"] else ""), cell),
                     Paragraph(short_basic(f["basic"]), cell),
                     str(f["severity"]),
                     Paragraph(f["verdict"], vcell),
                     Paragraph(f["evidence"], cell)])
    t = Table(rows, colWidths=[0.72 * inch, 2.05 * inch, 0.95 * inch, 0.38 * inch, 1.4 * inch, 1.7 * inch],
              repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f3864")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, 0), 8.5),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d8dfe8")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fb")]),
    ] + vstyles))
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
    el.append(Paragraph("Independent service &mdash; not affiliated with FMCSA or any state agency. Prepared from public "
                        "FMCSA SMS/MCMIS data. Identifies records that may merit a DataQs Request for Data Review; not "
                        "legal advice. Correction decisions are made solely by FMCSA and state reviewing agencies. "
                        "'Challengeable' reflects our reading of the public record; your evidence determines what is "
                        "actually filed.", small))
    doc.build(el)
    return path


@app.route("/send/<int:lead_id>", methods=["POST"])
def send_audit(lead_id):
    import smtplib
    from email.message import EmailMessage
    from email.utils import formataddr
    from datetime import date

    cfg = email_cfg()
    if not cfg.get("smtp_user"):
        return jsonify(error="Set SMTP_USER (your from-address) first"), 400
    if not cfg.get("api_key") and not cfg.get("smtp_pass"):
        return jsonify(error="Email not configured. On the cloud, set BREVO_API_KEY "
                             "(send over HTTPS). Locally you can use smtp_pass instead."), 400
    to_addr = (request.get_json(force=True).get("email") or "").strip()
    if "@" not in to_addr:
        return jsonify(error="No valid email on this lead"), 400

    lead, findings, summary, fetched = _build_audit(lead_id)
    if lead is None:
        return jsonify(error="lead not found"), 404
    pdf_path = _render_pdf(lead, findings, summary, fetched)

    with open(TEMPLATE_FILE, encoding="utf-8") as f:
        tpl = f.read()
    alerts = ", ".join(summary["alert_basics"]) or "multiple categories"
    for token, val in [("[COMPANY]", lead["company"]), ("[DOT]", lead["dot_number"]),
                       ("[TOTAL]", str(summary["total_viols"])),
                       ("[CHALLENGE]", str(summary["n_challenge"])),
                       ("[ALERTS]", alerts),
                       ("[MY_NAME]", cfg.get("my_name", "")),
                       ("[MY_PHONE]", cfg.get("my_phone", ""))]:
        tpl = tpl.replace(token, val)
    lines = tpl.strip().splitlines()
    subject = lines[0].replace("Subject:", "").strip()
    body = "\n".join(lines[1:]).strip()
    from_name = cfg.get("from_name") or cfg["smtp_user"]

    if cfg.get("api_key"):
        # Brevo transactional email over HTTPS (port 443) - works on hosts that
        # block SMTP (Railway does). Sender must be a verified sender in Brevo.
        import base64
        import requests
        with open(pdf_path, "rb") as f:
            pdf_b64 = base64.b64encode(f.read()).decode()
        payload = {
            "sender": {"name": from_name, "email": cfg["smtp_user"]},
            "to": [{"email": to_addr}],
            "subject": subject,
            "textContent": body,
            "attachment": [{"content": pdf_b64, "name": pdf_filename(lead)}],
        }
        try:
            r = requests.post("https://api.brevo.com/v3/smtp/email",
                              headers={"api-key": cfg["api_key"],
                                       "content-type": "application/json",
                                       "accept": "application/json"},
                              json=payload, timeout=30)
            if r.status_code >= 300:
                return jsonify(error="Send failed ({}): {}".format(
                    r.status_code, r.text[:300])), 500
        except Exception as e:
            return jsonify(error="Send failed: {}".format(e)), 500
    else:
        # SMTP fallback (local dev only - blocked on Railway)
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = formataddr((from_name, cfg["smtp_user"]))
        msg["To"] = to_addr
        msg.set_content(body)
        with open(pdf_path, "rb") as f:
            msg.add_attachment(f.read(), maintype="application", subtype="pdf",
                               filename=pdf_filename(lead))
        try:
            port = int(cfg["smtp_port"])
            if port == 465:
                server = smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=30)
            else:
                server = smtplib.SMTP(cfg["smtp_host"], port, timeout=30)
                server.starttls()
            with server:
                server.login(cfg["smtp_user"], cfg["smtp_pass"])
                server.send_message(msg)
        except Exception as e:
            return jsonify(error="Send failed: {}".format(e)), 500

    today = date.today().strftime("%m/%d/%Y")
    con = db()
    con.execute("UPDATE leads SET email=?, audit_sent='Yes', status='Audit Emailed', "
                "last_contact=?, first_contact=CASE WHEN first_contact IS NULL OR "
                "first_contact='' THEN ? ELSE first_contact END WHERE id=?",
                (to_addr, today, today, lead_id))
    con.commit()
    con.close()
    return jsonify(ok=True, sent_to=to_addr)


TEMPLATE_EDIT_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Email template</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:16px;background:#f5f7fa;color:#1a2733}
h2{margin:0 0 4px}.sub{color:#5b6b7a;font-size:12.5px;margin-bottom:10px}
textarea{width:100%;height:60vh;font-family:Consolas,monospace;font-size:13px;padding:10px;
border:1px solid #c3ceda;border-radius:8px;box-sizing:border-box}
.tok{background:#e8eef7;border-radius:6px;padding:1px 6px;font-size:11.5px;margin-right:4px;white-space:nowrap}
button{margin-top:10px;padding:9px 20px;background:#16a34a;color:#fff;border:none;border-radius:8px;font-size:14px}
a{color:#0563c1}.saved{color:#16a34a;font-weight:600;margin-left:10px}</style></head><body>
<h2>Email template</h2>
<div class="sub">First line is the subject. These auto-fill per carrier:
<span class="tok">[COMPANY]</span><span class="tok">[DOT]</span><span class="tok">[TOTAL]</span>
<span class="tok">[CHALLENGE]</span><span class="tok">[ALERTS]</span><span class="tok">[MY_NAME]</span>
<span class="tok">[MY_PHONE]</span></div>
<form method="post"><textarea name="template">{{tpl}}</textarea><br>
<button>Save</button>{% if saved %}<span class="saved">saved ✓</span>{% endif %}
<a href="/template?reset=1" style="margin-left:14px">Load recommended default</a>
<a href="/" style="margin-left:14px">← back to tracker</a></form></body></html>"""


@app.route("/template", methods=["GET", "POST"])
def template_editor():
    if request.method == "POST":
        with open(TEMPLATE_FILE, "w", encoding="utf-8") as f:
            f.write(request.form.get("template", ""))
        return render_template_string(TEMPLATE_EDIT_PAGE, tpl=request.form.get("template", ""), saved=True)
    if request.args.get("reset") == "1":
        with open(TEMPLATE_FILE, "w", encoding="utf-8") as f:
            f.write(RECOMMENDED_TEMPLATE)
    with open(TEMPLATE_FILE, encoding="utf-8") as f:
        return render_template_string(TEMPLATE_EDIT_PAGE, tpl=f.read(), saved=False)


if __name__ == "__main__":
    # 0.0.0.0 = reachable from other devices on your local network (phone on
    # same Wi-Fi). No auth exists yet — do NOT expose this to the public
    # internet; for remote access use a private tunnel (e.g. Tailscale).
    app.run(host="0.0.0.0", port=8765, debug=False)
