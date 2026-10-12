# Phishing Email Analyser

A privacy-first educational phishing email triage tool.

## Project purpose

The Phishing Email Analyser identifies common phishing and social-engineering
warning signs in pasted email content.

The project is designed as a cybersecurity learning project.

It does not attempt to definitively determine whether an email is malicious.

## Privacy

The application performs analysis entirely inside the visitor's web browser.

Email contents are not:

- uploaded to a server
- sent to an AI provider
- sent to an external API
- stored in a database
- sent to an analytics service

The application does not require:

- an account
- an API key
- a backend
- a database
- paid services

## Analysis Indicators
- urgency/pressure language
- account suspension threats
- password requests
- MFA/verification code requests
- payment/gift-card requests
- bank details changes
- credential harvesting language
- shortened/suspicous/raw IP address URLs
- potential misleading links
- impersonation language
- executable/unusual attachments
- marco requests
- invoice language
- sender/reply-to mismatches
- SPF failures
- DKIM failures
- DMARC failures

## Scoring
- 0-29 : Low Risk
- 30-59 : Suspicous
- 60-100 : High Risk
The score is an accumalation of detected warning signs (NOT a probability).

## Demonstration
- obvious phishing
- sophisticated phishing
- fake Microsoft 365 warning
- fake parcel delivery
- fake invoice / BEC
- legitimate email

## Technologies

The application uses:

- HTML
- CSS
- JavaScript

No framework or package manager is required.

## Project structure

```text
phishing-email-analyser/
├── index.html
├── style.css
├── app.js
└── README.md