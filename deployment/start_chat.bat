@echo off
cd /d %~dp0..
python -m server.chat_server.main
pause
