@echo off
cd /d "%~dp0"
echo === Building Standalone LAN-Chat.exe ===
pip install --upgrade pyinstaller -r requirements.txt

pyinstaller --onefile --name "LAN-Chat" ^
  --hidden-import=uvicorn.logging ^
  --hidden-import=uvicorn.loops.auto ^
  --hidden-import=uvicorn.protocols.http.auto ^
  --hidden-import=uvicorn.protocols.websockets.auto ^
  --hidden-import=uvicorn.lifespan.on ^
  --collect-all=zeroconf --collect-all=ifaddr ^
  --hidden-import=qrcode ^
  --hidden-import=cryptography ^
  lan_chat_app.py

echo.
echo Build complete! Share dist\LAN-Chat.exe (double-click to run).
pause
