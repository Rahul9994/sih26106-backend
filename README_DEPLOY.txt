BACKEND — for Render (or any Python-capable free host)
================================================================
This is a Flask API only now — it no longer serves the frontend.
Deploy it separately from the frontend zip.

⚠️ SECURITY: the original .env you had contained real, live API keys
for Groq and OpenRouter. Those keys have been REMOVED from this
package. Since they were sitting in a zip you were about to upload
publicly, rotate/regenerate both keys now:
   - Groq:       https://console.groq.com
   - OpenRouter: https://openrouter.ai
Then put the NEW keys into your host's environment variables — never
back into a committed .env file.

STEPS (Render, free tier)
--------------------------
1. Push this backend/ folder to a GitHub repo (or use Render's "deploy
   from zip/manual" option if you don't want GitHub).

2. On render.com: New → Web Service → connect your repo.
   - Build command:  pip install -r requirements.txt
   - Start command:  gunicorn app:app --bind 0.0.0.0:$PORT
     (already set in Procfile, Render should detect it automatically)

3. Under Environment, add these variables (values from your NEW,
   rotated keys):
     GROQ_API_KEY
     GROQ_MODEL            (e.g. llama-3.3-70b-versatile)
     OPENROUTER_API_KEY
     OPENROUTER_MODEL      (e.g. meta-llama/llama-3.1-8b-instruct:free)
     CASE_ORG_NAME
     ALLOWED_ORIGIN         <- set to your ProFreeHost frontend URL
                                once you know it, e.g.
                                https://yoursite.profreehost.com
     FLASK_DEBUG            False

4. Deploy. Render gives you a URL like:
     https://your-app-name.onrender.com

5. Copy that URL into API_BASE in the frontend's script.js and
   gmail.js (see the frontend zip's instructions), then re-upload
   those two files to ProFreeHost.

NOTE: Render's free tier sleeps after ~15 min of inactivity — the
first request after idling can take 30-60s to wake up. That's normal.

GMAIL FEATURES
--------------
gmail_client.py uses Gmail App Passwords over IMAP/SMTP — no extra
setup needed beyond what's already in the code, but note this sends
user Gmail credentials to your backend on every request. Fine for a
personal/demo project; if this goes further, don't log those values
anywhere.
