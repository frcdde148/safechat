@echo off
cd /d %~dp0..
python -m server.as_server.main
pause
