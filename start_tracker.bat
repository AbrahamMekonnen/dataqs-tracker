@echo off
rem Starts the DataQs tracker + public Cloudflare tunnel.
rem The public URL appears in tunnel.log (search for trycloudflare.com).
cd /d C:\Users\ameko\dataqs-tracker
start "dataqs-app" /min python app.py
start "dataqs-tunnel" /min "C:\Program Files (x86)\cloudflared\cloudflared.exe" tunnel --url http://localhost:8765 --logfile C:\Users\ameko\dataqs-tracker\tunnel.log
echo Tracker starting. Public URL: check tunnel.log in a few seconds.
