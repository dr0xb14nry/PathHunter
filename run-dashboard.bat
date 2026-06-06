@echo off
REM One-click PathHunter dashboard launcher (Windows).
REM Double-click this file, or run it from a terminal.
cd /d "%~dp0"
echo Starting PathHunter dashboard...
python -m pathhunter.web --data data\generated --open
pause
