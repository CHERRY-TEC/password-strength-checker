# Password Strength Checker - Audit Report

- Generated: 2026-11-20T10:01:57
- Tool version: 1.0.0
- Total analysed records: 40
- Security note: only analysis metadata is stored; passwords are never saved.

## Executive Summary

| Metric | Value |
| --- | --- |
| Total records | 40 |
| Average score | 52.7/100 |
| Median score | 53.5/100 |
| Score range | 0 - 100 |
| Average length | 9.9 |
| Strong / very strong | 15 (38%) |
| Weak / very weak | 17 (42%) |

## Rating Distribution

| Rating | Count | Share |
| --- | ---: | ---: |
| Very Strong | 15 | 38% |
| Strong | 4 | 10% |
| Fair | 4 | 10% |
| Weak | 7 | 18% |
| Very Weak | 10 | 25% |

## Threshold Indicators

- **CRITICAL**: 42% of records are weak (17/40). Consider a password audit.
- **WARNING**: Average password length is only 9.9 characters (recommended: 12+).
- **CRITICAL**: At least one record is in the 'Very Weak' band (score 0).

## All Records

| ID | Label | Checked at | Score | Rating | Length | Issues |
| ---: | --- | --- | ---: | --- | ---: | --- |
| 1 | Campus WiFi guest | 2026-11-18 03:15 | 25 | Weak | 8 | Only 1 character type(s) used; Matches or contains a common password / dictionary word |
| 2 | Old library card | 2026-08-14 02:36 | 9 | Very Weak | 6 | Too short (6 characters; 12+ recommended); Only 1 character type(s) used; Matches or contains a common password / dictionary word; Contains a character sequence or keyboard pattern |
| 3 | Dorm router | 2026-10-09 09:16 | 9 | Very Weak | 6 | Too short (6 characters; 12+ recommended); Only 1 character type(s) used; Matches or contains a common password / dictionary word; Contains a character sequence or keyboard pattern |
| 4 | Club signup | 2026-11-04 09:03 | 14 | Very Weak | 6 | Too short (6 characters; 12+ recommended); Only 2 character type(s) used; Matches or contains a common password / dictionary word; Contains a character sequence or keyboard pattern |
| 5 | Lab workstation | 2026-10-30 06:04 | 17 | Very Weak | 7 | Too short (7 characters; 12+ recommended); Only 1 character type(s) used; Matches or contains a common password / dictionary word |
| 6 | Alumni portal | 2026-11-02 06:57 | 30 | Weak | 8 | Only 2 character type(s) used; Matches or contains a common password / dictionary word |
| 7 | Admin console | 2026-08-28 23:38 | 15 | Very Weak | 5 | Too short (5 characters; 12+ recommended); Only 1 character type(s) used; Matches or contains a common password / dictionary word |
| 8 | Print kiosk | 2026-08-30 08:06 | 7 | Very Weak | 6 | Too short (6 characters; 12+ recommended); Only 1 character type(s) used; Matches or contains a common password / dictionary word; High character repetition (83%) |
| 9 | Shared calendar | 2026-10-25 15:45 | 23 | Weak | 8 | Only 1 character type(s) used; Matches or contains a common password / dictionary word |
| 10 | Sports forum | 2026-09-30 23:22 | 23 | Weak | 8 | Only 1 character type(s) used; Matches or contains a common password / dictionary word |
| 11 | Music account | 2026-10-29 13:42 | 25 | Weak | 8 | Only 1 character type(s) used; Matches or contains a common password / dictionary word |
| 12 | Guest laptop | 2026-09-29 08:32 | 17 | Very Weak | 6 | Too short (6 characters; 12+ recommended); Only 1 character type(s) used; Matches or contains a common password / dictionary word |
| 13 | Weather app | 2026-09-23 16:46 | 17 | Very Weak | 6 | Too short (6 characters; 12+ recommended); Only 1 character type(s) used; Matches or contains a common password / dictionary word |
| 14 | Course forum | 2026-10-18 04:06 | 31 | Weak | 8 | Only 2 character type(s) used; Contains a character sequence or keyboard pattern |
| 15 | Library catalogue | 2026-09-09 08:55 | 74 | Strong | 11 | - |
| 16 | Email backup | 2026-11-15 14:11 | 81 | Very Strong | 11 | - |
| 17 | Cloud drive | 2026-08-10 06:09 | 43 | Fair | 8 | Matches or contains a common password / dictionary word |
| 18 | Banking demo | 2026-10-31 01:26 | 85 | Very Strong | 11 | - |
| 19 | Research wiki | 2026-09-27 23:02 | 83 | Very Strong | 12 | - |
| 20 | Dev repository | 2026-11-10 22:22 | 83 | Very Strong | 10 | - |
| 21 | VPN client | 2026-09-12 03:09 | 80 | Very Strong | 10 | - |
| 22 | Phone hotspot | 2026-08-05 06:59 | 85 | Very Strong | 11 | - |
| 23 | Gaming account | 2026-08-19 12:32 | 48 | Fair | 14 | Matches or contains a common password / dictionary word |
| 24 | Photo storage | 2026-08-08 16:31 | 85 | Very Strong | 11 | - |
| 25 | Notebook app | 2026-09-01 05:03 | 76 | Strong | 9 | - |
| 26 | Messaging app | 2026-10-23 05:50 | 85 | Very Strong | 11 | - |
| 27 | Shopping cart | 2026-08-01 17:50 | 80 | Very Strong | 10 | - |
| 28 | Fitness tracker | 2026-11-14 16:37 | 92 | Very Strong | 12 | - |
| 29 | Recipe box | 2026-11-16 05:32 | 77 | Strong | 10 | - |
| 30 | Travel planner | 2026-10-31 03:22 | 85 | Very Strong | 11 | - |
| 31 | Personal wiki | 2026-09-25 07:58 | 69 | Strong | 28 | Only 1 character type(s) used; High character repetition (54%) |
| 32 | Password manager | 2026-11-01 08:01 | 100 | Very Strong | 16 | - |
| 33 | Server SSH key | 2026-11-03 11:46 | 100 | Very Strong | 17 | - |
| 34 | Encryption test | 2026-11-05 07:31 | 100 | Very Strong | 16 | - |
| 35 | Security audit | 2026-09-01 16:16 | 59 | Fair | 15 | Contains a character sequence or keyboard pattern |
| 36 | Strong passphrase | 2026-09-27 13:08 | 92 | Very Strong | 25 | High character repetition (32%) |
| 37 | Boundary: single char | 2026-09-10 18:27 | 17 | Very Weak | 1 | Too short (1 character; 12+ recommended); Only 1 character type(s) used |
| 38 | Boundary: two chars | 2026-10-26 10:34 | 26 | Weak | 2 | Too short (2 characters; 12+ recommended); Only 2 character type(s) used |
| 39 | Boundary: eight chars | 2026-10-12 09:08 | 40 | Fair | 8 | Contains a character sequence or keyboard pattern |
| 40 | Edge: empty password | 2026-08-14 12:00 | 0 | Very Weak | 0 | Empty password |

## Common Issues

| Issue | Count |
| --- | ---: |
| Matches or contains a common password / dictionary word | 15 |
| Only 1 character type(s) used | 13 |
| Too short (6 characters; 12+ recommended) | 6 |
| Contains a character sequence or keyboard pattern | 6 |
| Only 2 character type(s) used | 4 |
| Too short (7 characters; 12+ recommended) | 1 |
| Too short (5 characters; 12+ recommended) | 1 |
| High character repetition (83%) | 1 |
| High character repetition (54%) | 1 |
| High character repetition (32%) | 1 |
| Too short (1 character; 12+ recommended) | 1 |
| Too short (2 characters; 12+ recommended) | 1 |
| Empty password | 1 |

---
*Generated locally by Password Strength Checker v1.0.0.*
