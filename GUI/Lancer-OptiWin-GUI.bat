@echo off
title OptiWin GUI
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0OptiWin-GUI.ps1"
