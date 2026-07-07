@echo off
title PromptShield Backend Server
echo Starting PromptShield Flask Backend API...
cd backend
call .\venv\Scripts\activate.bat
python app.py
pause
