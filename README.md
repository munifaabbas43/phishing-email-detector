# Phishing Email Detector

Student: Munifa Abbas
Course: DACS Batch #56, PNY Trainings, Arfa Tower, Lahore

## About this project

This is a rule based phishing email scanner written in Python. It is not a
machine learning model, I built it as a scoring system using the red flags
covered in the cybersecurity part of my course: spoofed display names,
mismatched sender and link domains, urgency language, suspicious top level
domains, and dangerous attachment types.

Each rule adds points to a risk score, and the final score maps to a
verdict of Low Risk, Medium Risk, or High Risk. I made sure the tool prints
out the exact reasons behind the score instead of just a number, since that
was the part I actually cared about, being able to explain why something
looks like phishing.

## How the scoring works

| Indicator | Points |
|-----------|--------|
| Sender domain does not match the brand named in the display name | +25 |
| Sender domain uses a commonly abused TLD (.tk, .xyz, .ru, etc) | +15 |
| Each urgency/pressure phrase found in the body | +5 each |
| Link domain does not match sender domain | +10 |
| Link uses a raw IP address instead of a domain | +20 |
| Link uses a suspicious TLD | +10 |
| Attachment with a dangerous extension (.exe, .scr, .js, etc) | +30 |
| Compressed attachment (.zip, .rar, .7z) | +10 |

Verdict thresholds:

- 0 to 19: LOW RISK
- 20 to 49: MEDIUM RISK
- 50 and above: HIGH RISK

## Requirements

- Python 3.8 or newer
- No external libraries needed, it only uses the standard library
  (`email`, `re`, `urllib.parse`)

## How to run it

```bash
git clone https://github.com/your-username/phishing-email-detector.git
cd phishing-email-detector
python3 phishing_detector.py sample_emails/phishing_example.eml
```

Two sample `.eml` files are included under `sample_emails/` so the tool can
be tested right away without needing a real inbox:

- `phishing_example.eml` - a fake PayPal email with a spoofed domain,
  urgency language and a mismatched link, scores as HIGH RISK
- `legit_example.eml` - a normal class schedule email, scores as LOW RISK

## Running the tests

```bash
python3 -m unittest test_phishing_detector.py -v
```

## Example output

```
============================================================
Subject   : Urgent: Your account will be suspended
From      : PayPal Security <security@paypa1-verify.tk>
Risk Score: 90
Verdict   : HIGH RISK
============================================================
Reasons:
  - Display name mentions 'paypal' but sender domain is 'paypa1-verify.tk', this is a classic brand spoofing pattern
  - Sender domain uses a commonly abused TLD: .tk
  - Urgency/pressure language found: immediately, suspended, act now, click here, confirm your identity
  - Link domain 'paypa1-secure-login.tk' does not match sender domain 'paypa1-verify.tk'
  - Link uses a suspicious TLD: paypa1-secure-login.tk
```

## Project structure

```
phishing-email-detector/
├── phishing_detector.py
├── test_phishing_detector.py
├── sample_emails/
│   ├── phishing_example.eml
│   └── legit_example.eml
├── README.md
└── LICENSE
```

## Limitations

This is a rule based tool, so it can be fooled by phishing emails that do
not match the specific patterns I coded for, and it can occasionally flag a
legitimate email that happens to use urgent language, like a real account
security notice. It is meant to support manual review, not replace it.

## What I learned

Building the sender/link domain comparison logic took a few tries to get
right, since a naive string match flags too many false positives on
subdomains. I also learned how much of phishing detection comes down to
just checking whether the visible brand name actually matches the technical
sender domain, which is the check that caught the most in my testing.

## Future improvements

- Add SPF/DKIM/DMARC header validation
- Add a check against a known malicious domain list
- Turn this into a simple web app where a user can paste email content
  directly instead of uploading a .eml file
