# 🔐 Phishing Link Detector

A web-based cybersecurity tool built with Python and Flask to analyze URLs and identify potential phishing threats.

## 📌 Overview

The Phishing Link Detector analyzes a submitted URL using a combination of local URL heuristics and VirusTotal threat intelligence.

The application provides security-related information about the submitted URL to help users identify potentially suspicious or malicious links.

## ✨ Features

- 🔎 URL analysis
- 🛡️ Local phishing detection heuristics
- 🌐 VirusTotal URL analysis
- 📊 Suspicion/risk assessment
- 💻 Web-based interface using Flask
- ⚡ Simple and user-friendly interface

## 🛠️ Technologies Used

- Python
- Flask
- VirusTotal API
- Requests
- HTML
- CSS
- JavaScript

## 🧠 How It Works

1. The user submits a URL through the web interface.
2. The application parses and analyzes the URL locally.
3. It checks for common characteristics associated with phishing URLs.
4. The URL is submitted to VirusTotal for additional threat intelligence.
5. The application combines the available results and displays the analysis.

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/kshitij-1789/phishing-link-detector.git
