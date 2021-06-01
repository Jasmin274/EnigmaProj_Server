@ECHO OFF
TITLE Enigma Project Module Downloading

ECHO ==========================
ECHO PYCRYPTODOME DOWNLOAD
ECHO ============================
pip install pycryptodome==3.9.9

ECHO ==========================
ECHO SPEECH RECOGNITION DOWNLOAD
ECHO ============================
pip install SpeechRecognition

ECHO ==========================
ECHO IP ADDRESS
ECHO ============================
ipconfig | findstr IPv4

PAUSE



