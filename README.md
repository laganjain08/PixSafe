# PixSafe – AI-Based Image and URL Scanner

## About
PixSafe is a web-based security tool that helps users identify potentially unsafe URLs and suspicious images. It provides a simple Safe/Unsafe result with a threat level for easy understanding.
## Live Demo

[Visit PixSafe](https://pix-safe-nine.vercel.app/scan.html)

## Features
- Scan URLs for suspicious or unsafe patterns.
- Scan images for security-related indicators.
- Detect suspicious URLs, typosquatting and risky patterns.
- Check image metadata and other security indicators.
- Display threat levels such as Safe, Medium, High and Critical.
- Simple and user-friendly interface.

## Technologies Used
- HTML
- CSS
- JavaScript
- Node.js
- Express.js
- REST APIs

## How It Works
1. User enters a URL or uploads an image.
2. Frontend sends the data to the backend.
3. Backend performs security checks.
4. The result is analyzed and classified.
5. PixSafe displays the security status and threat level.

## Project Structure
```text
PixSafe/
├── frontend/
└── backend/
Installation & Setup
Backend
cd backend
npm install
npm start
Frontend

Open the frontend folder and run the website using a local server.

Limitations
Results depend on the security checks implemented in the project.
It cannot guarantee that every URL or image is completely safe.
It is intended as a security-assistance tool, not professional security software.
Disclaimer

PixSafe is developed for educational and security-awareness purposes. Users should not rely solely on its results for security-critical decisions.

Future Enhancements
Machine learning-based threat detection.
Advanced image and URL analysis.
Database integration for threat history.
Improved detection accuracy.
