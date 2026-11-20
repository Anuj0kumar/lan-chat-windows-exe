# Offgrid Teams

**Zero-Internet, End-to-End Encrypted Local Network Communication, File Vault & WebRTC Collaboration Platform**

Offgrid Teams is a self-hosted, offline-first team messaging and collaboration server engineered for environments where internet connectivity is unavailable, restricted, or undesirable—including R&D labs, factories, startups, college campuses, hostels, and air-gapped field operations. A single executable or Python process turns any local Wi-Fi network, Ethernet LAN, or mobile hotspot into a private, zero-data-cost workspace.

---

## 1. Key Capabilities

### Security & End-to-End Encryption (E2EE)
- **Client-Side E2EE (`ECDH P-256` + `AES-GCM 256`)**: Direct messages, group rooms, live polls, side threads, and uploaded `.enc` media/files are encrypted in the browser before transmission.
- **Safety Number Verification**: Deterministic 6-block SHA-256 key fingerprint comparison (`🔐`) for 1-on-1 DM peers to detect man-in-the-middle tampering.
- **Device & Access Governance**: 1-IP-1-Account registration lock with PIN-verified DHCP IP transfer, passcode-protected private groups, announcement-only channels, and configurable disappearing message timers (`1m`, `1h`, `24h`).
- **Zero-Config TLS & Discovery**: Automatic self-signed X.509 certificate generation (`cert.pem`, `key.pem`) bound to the host's active LAN IP and `chat.local`, paired with mDNS (`zeroconf`) and scannable terminal/in-app QR onboarding.

### Real-Time Messaging & Collaboration
- **Rich Messaging**: 1-on-1 DMs and group channels with Slack-style side threads, pinned messages, emoji reactions, live polls, reply quotes, and delivered/read receipts.
- **Syntax-Highlighted Code Blocks**: Single-pass tokenizer supporting Python, Java, C++, JavaScript, SQL, and JSON with one-click copy.
- **Shared Files & PDF Vault**: Chunked uploads up to **50 MB** per file with an in-app PDF viewer, encrypted audio voice notes, and automatic 7-day retention pruning.

### Peer-to-Peer WebRTC Audio, Video & Screen Sharing
- **1-on-1 Calls & Multi-User Group Huddles**: Direct P2P audio/video calling and WebRTC mesh huddles in group rooms.
- **Screen Sharing & PiP Mode**: Desktop and mobile screen sharing during video calls with a collapsible floating Picture-in-Picture (PiP) widget so users can browse chats mid-call.
- **Push-to-Talk & Call Recording**: Spacebar walkie-talkie mode and client-side `MediaRecorder` call capture saved directly to the room's encrypted vault.

### 100% Offline Local AI & Automation
- **Local AI Assistant (`/summarize`, `/ask`)**: Integrates with local **Ollama** (`127.0.0.1:11434`) or **`llama.cpp`** (`127.0.0.1:8080`) servers—and includes a built-in zero-dependency **Offline Extractive AI & RAG** fallback over decrypted room messages and shared files.
- **Incoming Webhooks**: `POST /api/webhooks/{room_id}` endpoint compatible with local Gitea, GitLab, Jenkins, and custom monitoring scripts.
- **Productivity Slash Commands**: `/todo`, `/remind <time> <note>`, `/webhook`, and `/help`.

### Reliability, Search & Admin Control Center
- **SQLite WAL + FTS5 Search**: Write-Ahead Logging with non-blocking `asyncio.to_thread` execution and FTS5 full-text indexing across rooms, senders, and filenames (`🌐 FTS5`).
- **IndexedDB Offline Persistence**: Client-side `lanChatIDB` caches up to 150 messages per room and queues offline text/files/voice notes for automatic upload upon reconnect.
- **Admin Control Center (`🛡️`)**: Real-time server telemetry, user role promotion/demotion, IP-lock resets, user suspension/banning, on-demand upload cleanup, and global announcements.
- **White-Label & Export**: Configurable branding (`LAN_CHAT_BRAND_NAME`, `LAN_CHAT_BRAND_TAGLINE`, `LAN_CHAT_ACCENT_COLOR`), department/status tags, and client-side `.txt`/`.json` chat exports.

---

## 2. System Architecture

```text
+-------------------------------------------------------------------+
|                   Client Devices (Laptop / Mobile)                |
|  PWA Shell (Service Worker)  |  Web Crypto (ECDH + AES-GCM)       |
|  IndexedDB (History/Outbox)  |  WebRTC (P2P Audio/Video/Screen)   |
+---------------------------------+---------------------------------+
                                  |  HTTPS (TLS) + WSS (:8000)
+---------------------------------v---------------------------------+
|                Offgrid Teams Server (FastAPI + Uvicorn)           |
|  - Auth & Role Guard         - WebSocket ConnectionManager        |
|  - Chunked Upload/Vault      - mDNS (chat.local) & QR Generator   |
|  - Incoming Webhooks API     - Local AI Router (Ollama/Fallback)  |
+----------------+--------------------------------+-----------------+
                 |                                |
    +------------v------------+      +------------v------------+
    |   SQLite (WAL + FTS5)   |      |   Local File Storage    |
    |   lan_chat.db           |      |   lan_uploads/ (.enc)   |
    +-------------------------+      +-------------------------+
```

---

## 3. Quick Start

### Option A: Standalone Windows Executable (`.exe`)
1. Download `Offgrid-Teams.exe` from the repository's **Releases** page (or build it via `build_exe.bat`).
2. Double-click `Offgrid-Teams.exe` and allow Windows Firewall access on TCP port `8000`.
3. Scan the terminal QR code from any phone on the same Wi-Fi/hotspot, or open `https://<host-ip>:8000` in a browser.

### Option B: Run from Python Source
```bash
git clone https://github.com/Anuj0kumar/lan-chat-windows-exe.git
cd lan-chat-windows-exe
python -m venv .venv
.venv\Scripts\activate      # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python lan_chat_app.py
```

> **Windows Firewall (One-Time Admin Command if LAN clients cannot reach port 8000):**
> ```cmd
> netsh advfirewall firewall add rule name="Offgrid Teams 8000" dir=in action=allow protocol=TCP localport=8000
> ```

---

## 4. Configuration (Environment Variables)

| Variable | Default | Description |
| :--- | :--- | :--- |
| `LAN_CHAT_BRAND_NAME` | `Offgrid Teams` | White-label application title and login heading |
| `LAN_CHAT_BRAND_TAGLINE` | `Zero-data local Wi-Fi chat...` | Custom subtitle displayed on the login screen |
| `LAN_CHAT_ACCENT_COLOR` | *(built-in purple)* | Custom CSS hex accent color (e.g. `#0f766e`) |
| `LAN_CHAT_ADMINS` | *(first registered user)* | Comma-separated usernames granted `admin` role on signup |
| `LAN_CHAT_WEBHOOK_SECRET` | *(none)* | Optional shared secret required via `X-Webhook-Secret` header |
| `OLLAMA_URL` | `http://127.0.0.1:11434/api/generate` | Local Ollama endpoint for `/summarize` and `/ask` |
| `OLLAMA_MODEL` | `llama3.2` | Ollama model name |
| `LLAMA_CPP_URL` | `http://127.0.0.1:8080/v1/chat/completions` | Fallback local `llama.cpp` OpenAI-compatible endpoint |

---

## 5. API & Slash Commands Reference

### Core Endpoints
| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/api/auth` | `POST` | Register or authenticate user with PIN + device IP lock |
| `/api/config` | `GET` | Retrieve white-label branding configuration |
| `/api/rooms` | `GET`, `POST` | List group rooms or create passcode/announcement-only rooms |
| `/api/rooms/{room_id}/join` | `POST` | Verify passcode and join a protected room |
| `/api/search?q=...` | `GET` | Global SQLite FTS5 search across rooms, senders, and filenames |
| `/api/ai` | `POST` | Run local LLM or offline extractive `/summarize` and `/ask` RAG |
| `/api/webhooks/{room_id}` | `POST` | Push automated Gitea/GitLab/Jenkins/script alerts into a room |
| `/api/admin/overview` | `GET` | Server metrics and user management data (Admin only) |
| `/ws/{username}` | `WS` | Real-time messaging, presence, receipts, and WebRTC signaling |

### Composer Slash Commands
- `/summarize` — Generate an offline recap and action-item summary of the active room.
- `/ask <question>` — Query decrypted room messages and shared files via local RAG.
- `/todo <task>` — Post a formatted team action item card.
- `/remind <time> <note>` — Schedule a local timer alert (e.g., `/remind 10m Check build`).
- `/webhook` — Display the room's `curl` webhook integration snippet.
- `/help` — List all available slash commands.

---

## 6. Building & Automated Testing

### Build Standalone Windows `.exe`
```cmd
build_exe.bat
```
Output binary is generated at `dist\Offgrid-Teams.exe`.

### Run Automated Test & Load Suite
```bash
pytest test_lan_chat.py -v
```
The test suite (`test_lan_chat.py`) validates authentication, admin RBAC, passcode/announcement-only enforcement, incoming webhooks, SQLite FTS5 search, offline AI RAG, and WebSocket burst message delivery using an isolated temporary database. GitHub Actions (`.github/workflows/ci.yml`) runs this suite on both Ubuntu and Windows on every push to `main`.

---

## 7. Security Notes
- **Self-Signed HTTPS**: Because Offgrid Teams operates without internet CA access, browsers display a one-time certificate warning on first visit (`Advanced → Proceed`). Enabling HTTPS is required by browsers for microphone, camera, screen sharing, and Web Crypto APIs on non-localhost LAN IPs.
- **E2EE Scope**: End-to-end encryption keys are generated and stored on client devices; the server relays and persists ciphertext without access to plaintext DM/group keys. Server-side FTS5 search indexes plaintext/webhook messages and file metadata while preserving client-side in-room search for decrypted E2EE messages.