#!/usr/bin/env python3
"""
Phishing Email Detector
Author: Munifa Abbas
Course: DACS Batch #56, PNY Trainings, Arfa Tower, Lahore

A rule based tool that scans an email (.eml file or raw text) and flags
common phishing indicators. This is not a machine learning model, it is a
scoring system built from the red flags I researched during the
cybersecurity module: suspicious sender domains, mismatched links, urgency
language, spoofed display names, and known phishing keywords.

Each indicator adds points to a risk score. At the end the tool prints a
verdict: Low Risk, Medium Risk, or High Risk, along with the specific
reasons behind the score so the result is explainable and not a black box.
"""

import argparse
import email
import re
import sys
from email import policy
from urllib.parse import urlparse


URGENCY_WORDS = [
    "urgent", "immediately", "verify your account", "suspended",
    "act now", "limited time", "click here", "confirm your identity",
    "your account will be closed", "unusual activity", "password expires",
    "final notice", "action required",
]

SUSPICIOUS_TLDS = [
    ".ru", ".cn", ".tk", ".xyz", ".top", ".club", ".gq", ".info",
]

FREE_MAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
]

COMMON_BRANDS = [
    "paypal", "apple", "microsoft", "amazon", "netflix", "bank",
    "dhl", "fedex", "google",
]


def load_email(path):
    with open(path, "rb") as f:
        return email.message_from_binary_file(f, policy=policy.default)


def get_body_text(msg):
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
        return "\n".join(parts)
    else:
        try:
            return msg.get_content()
        except Exception:
            return ""


def extract_links(text):
    return re.findall(r"https?://[^\s\)\]\"'<>]+", text)


def check_sender_domain(from_header, score, reasons):
    match = re.search(r"@([\w.-]+)", from_header)
    if not match:
        reasons.append("Could not parse a sender domain from the From header (suspicious on its own)")
        return score + 15

    domain = match.group(1).lower()

    for brand in COMMON_BRANDS:
        if brand in from_header.lower() and brand not in domain:
            reasons.append(
                f"Display name mentions '{brand}' but sender domain is '{domain}', "
                f"this is a classic brand spoofing pattern"
            )
            score += 25

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append(f"Sender domain uses a commonly abused TLD: {tld}")
            score += 15

    return score


def check_urgency_language(body, score, reasons):
    lowered = body.lower()
    hits = [w for w in URGENCY_WORDS if w in lowered]
    if hits:
        reasons.append(f"Urgency/pressure language found: {', '.join(hits[:5])}")
        score += 5 * len(hits)
    return score


def check_links(body, from_domain, score, reasons):
    links = extract_links(body)
    for link in links:
        parsed = urlparse(link)
        link_domain = parsed.netloc.lower()

        if from_domain and link_domain and from_domain not in link_domain and link_domain not in from_domain:
            reasons.append(
                f"Link domain '{link_domain}' does not match sender domain '{from_domain}'"
            )
            score += 10

        for tld in SUSPICIOUS_TLDS:
            if link_domain.endswith(tld):
                reasons.append(f"Link uses a suspicious TLD: {link_domain}")
                score += 10

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}", link_domain):
            reasons.append(f"Link uses a raw IP address instead of a domain name: {link_domain}")
            score += 20

    return score


def check_attachments(msg, score, reasons):
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            lowered = filename.lower()
            if lowered.endswith((".exe", ".scr", ".js", ".vbs", ".bat", ".jar")):
                reasons.append(f"Attachment has a dangerous file extension: {filename}")
                score += 30
            elif lowered.endswith((".zip", ".rar", ".7z")):
                reasons.append(f"Compressed attachment found, review manually: {filename}")
                score += 10
    return score


def get_verdict(score):
    if score >= 50:
        return "HIGH RISK"
    elif score >= 20:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"


def analyze_email(path):
    msg = load_email(path)
    from_header = msg.get("From", "")
    subject = msg.get("Subject", "")
    body = get_body_text(msg)

    from_domain_match = re.search(r"@([\w.-]+)", from_header)
    from_domain = from_domain_match.group(1).lower() if from_domain_match else ""

    score = 0
    reasons = []

    score = check_sender_domain(from_header, score, reasons)
    score = check_urgency_language(body, score, reasons)
    score = check_links(body, from_domain, score, reasons)
    score = check_attachments(msg, score, reasons)

    verdict = get_verdict(score)

    print("=" * 60)
    print(f"Subject   : {subject}")
    print(f"From      : {from_header}")
    print(f"Risk Score: {score}")
    print(f"Verdict   : {verdict}")
    print("=" * 60)
    if reasons:
        print("Reasons:")
        for r in reasons:
            print(f"  - {r}")
    else:
        print("No red flags detected by the current ruleset.")
    print()

    return {"score": score, "verdict": verdict, "reasons": reasons}


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Detector - DACS Batch 56 project by Munifa Abbas"
    )
    parser.add_argument("eml_file", help="Path to a .eml email file to analyze")
    args = parser.parse_args()

    try:
        analyze_email(args.eml_file)
    except FileNotFoundError:
        print(f"Error: could not find file {args.eml_file}")
        sys.exit(1)


if __name__ == "__main__":
    main()
