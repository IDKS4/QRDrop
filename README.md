# 📦 QRDrop

Transfer files between your phone and PC via QR code.
No app install on the phone — just a browser.

---

## 🚀 Installation (once)

```bash
# 1. Create a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# Mac / Linux
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Run

```bash
python server.py
```

Then open **http://localhost:8080** in your PC browser.

### Options

```bash
# Change port
python server.py --port 9000

# Change output folder
python server.py --output ~/Desktop/Received

# Auto-open browser on startup
python server.py --open-browser

# Combine everything
python server.py --port 9000 --output ~/Desktop/Received --open-browser
```

---

## 📱 How it works

### Phone → PC

1. Run `python server.py` on your PC
2. Open **http://localhost:8080** in your PC browser
3. A QR code appears automatically
4. Scan it with your phone (camera or QR app)
5. Select the file(s) to send
6. Tap **Send**
7. Files are saved to `~/Downloads/QRDrop/<session_id>/` on your PC ✅

### PC → Phone

1. On the PC page, scan the QR code with your phone to open the mobile page
2. Use the **"Share from PC"** section to select files
3. Click or **drag & drop** files onto the zone
4. They instantly appear in the **"Available files"** section on mobile
5. Tap a file to download it, or use **"Download all (.zip)"** ✅

### Send text / link (Phone → PC)

1. On the mobile page, use the **"Send text to PC"** section
2. Paste or type any text (link, password, note…)
3. Tap **Send**
4. The text instantly appears on the PC page with a **Copy** button ✅

> **Note:** Each session creates an isolated subfolder (`~/Downloads/QRDrop/<session_id>/`).
> Files persist on disk after the session closes.
> Sessions automatically expire after **30 minutes of inactivity**.

---

## ⚠️ Known issue — Chrome Android blocks HTTP

Since 2023, Chrome on Android may block HTTP connections to local IPs.
If the mobile page doesn't load: use **Firefox Mobile** instead.

---

## 📁 Project structure

```
qrdrop/
├── server.py           # Main FastAPI server
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── templates/
    ├── pc.html         # PC browser interface
    └── mobile.html     # Mobile browser interface
```

---

## ✨ Features

| Feature | Description |
|---|---|
| 📤 File upload | Phone → PC, multi-file, progress bar |
| 📥 File download | PC → Phone, tap to download |
| 🗜️ ZIP download | Download all PC files as a single .zip |
| 💬 Text sharing | Send text/links from phone to PC |
| 🖼️ Preview | Inline thumbnails for received images |
| 🔔 Notifications | Browser notification on each file/text received |
| 🗑️ Delete | Delete a received file from the PC |
| ⏱️ Auto-expiry | Sessions expire after 30 min of inactivity + countdown |
| ↺ Renew | Button to extend the current session |
| 🎨 MIME icons | File-type icons (image, video, audio, pdf…) |

---

## 🔒 Security

QRDrop is designed for **local network use only**. Built-in measures include:

- Per-session file isolation (dedicated subfolder)
- Path traversal and null byte protection on filenames
- Max 10 simultaneous sessions (memory DoS protection)
- Upload size limit: 500 MB per file
- HTTP security headers (CSP, X-Frame-Options, X-Content-Type-Options)
- Cryptographic session IDs (48-bit entropy)
- Trusted host restriction (TrustedHostMiddleware)
- Automatic session expiration on inactivity

> **Do not expose this server to the internet** without adding authentication.

---

## 🗺️ Roadmap

- [x] MVP: phone → PC upload
- [x] Multi-file upload with progress bar
- [x] PC → phone download
- [x] Per-session file isolation
- [x] Drag & drop on PC page
- [x] Text / link sharing (phone → PC)
- [x] ZIP download of all files
- [x] Browser notifications
- [x] File deletion from PC
- [x] Automatic session expiry (30 min)
- [x] Countdown + "Renew" button
- [x] MIME icons + image previews
- [ ] HTTPS support (self-signed certificate)
- [ ] Persistent session history across page reloads
