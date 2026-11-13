# LAN Chat — Windows 1-Click `.exe`

Zero-internet-data WhatsApp-style LAN chat, voice/video calls, and file sharing packaged as a standalone Windows `.exe`.

## How to Build the `.exe`

1. Extract this folder anywhere (e.g., `D:\Projects\lan-chat-windows-exe`).
2. Double-click **`build_exe.bat`** (or open CMD in this folder and run `build_exe.bat`).
3. Once finished, your standalone app is at **`dist\LAN-Chat.exe`**.
4. Copy `dist\LAN-Chat.exe` anywhere and double-click to run—other users on the same Wi-Fi/hotspot just scan the QR code!

## Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit: LAN Chat Windows EXE"
git branch -M main
git remote add origin https://github.com/<your-username>/lan-chat-windows-exe.git
git push -u origin main
```
