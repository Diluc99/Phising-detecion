# SOC Tier-1 Triage Playbook: Suspected Phishing Email

Companion to PhishingDetector. Use this when a user reports a suspicious email. The tool gives a risk score and a list of indicators. The analyst makes the final call.

## 1. Risk bands and default action

| Score | Verdict | Default action |
|-------|---------|----------------|
| 70 to 100 | PHISHING | Escalate to Tier 2. Block sender and URLs. Search for other recipients. |
| 40 to 69 | SUSPICIOUS | Manual review of every flagged indicator. Escalate if two or more strong signals are confirmed. |
| 0 to 39 | LIKELY SAFE | Close with a note. Tell the reporter why. |

The score is a heuristic. A high score with one weak signal can still be a false positive. A low score does not prove the email is safe.

## 2. Triage steps

1. **Receive the report.** Record who reported it, when, and whether they clicked a link, opened an attachment or entered credentials.
2. **Collect the evidence.** Get the full raw message (headers and body) or the original `.eml` file. Do not use a forwarded copy, because forwarding changes the headers.
3. **Load it into the dashboard.** Paste the raw email or upload the `.eml` file.
4. **Check authentication.** Read the SPF and DKIM results. A failure is a strong signal.
5. **Check the sender.** Compare the From, Reply-To and Return-Path domains. A mismatch suggests spoofing.
6. **Check the links.** Look for IP-based URLs, link shorteners, unusual top-level domains, `@` tricks, and link text that does not match the real destination.
7. **Check the content.** Look for brand impersonation, urgency language, and requests for credentials or personal data.
8. **Check attachments.** Flag executables, archives, scripts (`.ps1`, `.vbs`) and macro-enabled Office files.
9. **Record the verdict and IOCs** in the ticket, then escalate or close.

## 3. Indicators of compromise to record

- Sender address and the From, Reply-To and Return-Path domains
- Sending IP address from the headers
- All URLs and their final destination domains
- Attachment file names and extensions
- Subject line and any brand being impersonated

## 4. Signal reference

| Signal | What it suggests | MITRE ATT&CK |
|--------|------------------|--------------|
| SPF or DKIM failure | Sender not authorised for the domain | T1566 |
| From, Reply-To or Return-Path mismatch | Spoofed sender | T1656 |
| Brand impersonation | Pretending to be a trusted organisation | T1656 |
| IP-based, shortened or unusual-TLD URL | Disposable or hidden infrastructure | T1566.002, T1583.001 |
| `@` trick or link text mismatch | Disguised destination | T1566.002 |
| Risky attachment type | Malware delivery | T1566.001 |
| Urgency language | Pressure to act without checking | T1566 |
| Credential or personal data request | Harvesting | T1566 |

Heaviest weights in the scoring engine: sensitive data request (+35), SPF/DKIM failure (+30), IP-based URL (+25), Reply-To/From mismatch (+25).

## 5. When to escalate to Tier 2

- The reporter clicked a link, opened an attachment or entered credentials.
- The verdict is PHISHING.
- The same sender, domain or URL appears in other reported emails.
- The attachment is an executable or script.

## 6. Known limitations

- Rule-based detection can miss novel phishing and can flag legitimate marketing email.
- SPF and DKIM results depend on the headers present in the message and on DNS lookups.
- The tool does not detonate attachments or visit URLs. Do not click links from a reported email on a work machine.
