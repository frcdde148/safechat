@echo off
cd /d %~dp0..
python -m server.tgs_server.main
pause
