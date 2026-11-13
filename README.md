# Offline LAN Chat App

A zero-internet-data, end-to-end encrypted WhatsApp-style chat and calling web app built with **FastAPI**, **WebSockets**, and **SQLite**. Everything runs locally on your Wi-Fi router or phone hotspot with no external CDNs or cloud servers.

---

## 1. How to Initialize (Setup & Start)

### Option A: Run Directly with Python
1. Install dependencies once while online:
   ```bash
   pip install fastapi uvicorn python-multipart websockets qrcode zeroconf cryptography
   ```
2. Start the server:
   ```bash
   python lan_chat_app.py
   ```
3. On first launch, the app automatically creates `lan_chat.db` (SQLite WAL mode), `lan_uploads/`, and self-signed HTTPS certificates (`cert.pem` and `key.pem`) matching your current LAN IP.

### Option B: Build & Run as a Standalone Windows `.exe`
1. Run `build_exe.bat` inside the project folder once to package `dist\LAN-Chat.exe`.
2. Double-click `dist\LAN-Chat.exe` on any Windows PC (Python does not need to be installed on that machine).
3. If Windows Firewall pops up, allow access on **Private networks** so phones on the same Wi-Fi/hotspot can connect.

### Option C: Zero-Router Mode (Phone Hotspot)
1. Turn on **Mobile Hotspot** on any phone (keep **Mobile Data OFF** so zero data is used).
2. Connect your host laptop (running `lan_chat_app.py` or `LAN-Chat.exe`) and your friends' phones to that hotspot.

---

## 2. How to Use the App

### Step 1: Join from Any Device
* **On the host PC:** Open `https://127.0.0.1:8000` in your browser.
* **On phones and other laptops:** Scan the **QR code** printed in the terminal (or open the printed `https://<lan-ip>:8000` URL).
* **Trust the local certificate once:** Because the app uses a local self-signed HTTPS certificate (required for mic, camera, and encryption), tap **Advanced → Proceed** on the browser warning the first time you open it.

### Step 2: Log In with Username + PIN
* Enter a username (2–24 characters: letters, numbers, `_`, or `-`) and set a **4–8 digit PIN**.
* **1-IP-1-Account Lock:** Each local device IP can only register one username so nobody can create duplicate IDs. If your phone's IP changes later, enter your original username and PIN to transfer your session.

### Step 3: Chat, Reply, React, Edit & Delete
* **Groups & 1-on-1 DMs:** Chat in `# General`, create custom groups with **+ New**, or tap any person under **People (1-on-1)** for a private chat. Both DMs and group rooms show **E2EE 🔒** when connected over HTTPS or `127.0.0.1`.
* **Message Actions (`⋮`):** Tap or hover on any message and click `⋮` to **React** (`👍 ❤️ 😂 😮 😢 🙏`), **Reply** (quote), **Edit** (within 15 min of sending, or 1 min of being seen), **Delete for me**, or **Delete for everyone** (within 1 hour of sending, or 5 min of being seen).
* **Clear / Delete Chat:** Use **Clear Chat** in the top bar to wipe your local view of a conversation, or **Delete Group** if you created that group.

### Step 4: Voice Notes, Files, PDFs & Calling
* **Files & Images:** Click **Attach** (or press `Ctrl+V` to paste a clipboard image) to send encrypted files up to **50 MB** with a live upload progress bar. Old files in `lan_uploads/` are automatically cleaned up after 7 days.
* **In-App PDF Viewer:** Click **View** on any `.pdf` attachment to read it right inside the app, or **Download** to save a copy.
* **Voice Notes:** Tap **Mic** to record a voice note and tap **Stop** to send it as an inline audio player.
* **Voice & Video Calls:** Open any 1-on-1 DM and tap **Call** or **Video** in the header to start a direct peer-to-peer WebRTC call over your LAN.

### Step 5: Install as a Mobile App (PWA) & Offline Queue
* **Install:** Tap **Add to Home Screen** (or **Install app**) in your phone browser to launch LAN Chat full-screen.
* **Share:** Tap **Invite** in the sidebar to display a scannable QR code and copyable join URL right inside the app.
* **Refresh & Offline Queue:** Swipe down from the top of any chat until the refresh circle turns green to reload, and keep typing if Wi-Fi briefly drops—unsent messages show `⏳` and send automatically once reconnected.