---
title: GUI-Vil (p0-LUCR-1)
date: 2026-08-22
type: threat-actor
origin: Indonesia
motivation: Financial (cryptomining)
active_since: November 2021
tags:
  - type/threat-actor
  - platform/aws
  - category/cryptomining
  - category/financial
source:
  url: https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor/
  author: Permiso (p0 Labs)
  date: 2023
---

## Overview
GUI-Vil (tracked by Permiso/p0 Labs as **p0-LUCR-1**) is an Indonesia-based, financially motivated threat actor active since November 2021, operating out of ASNs belonging to PT. Telekomunikasi Selula and PT Telekomunikasi Indonesia. The group's defining trait is that it is **hands-on-keyboard** rather than automated — an "engaged attacker at the keyboard, ready to adapt" to each victim's environment — and it strongly prefers **GUI-based tools** (S3 Browser, the AWS Management Console) over CLI tooling, which is unusual among cloud-focused financial threat actors and provides distinct detection opportunities.

## Objective
Unauthorized cryptocurrency mining (XMRig/Monero) using compromised AWS accounts to provision large EC2 instances (xlarge and above) at the victim's expense. Per Permiso's assessment, the actor's direct crypto-mining profit is only "a sliver of the expense the victim organizations have to pay" — the primary damage is the victim's own inflated AWS bill.

## Initial Access
- Monitoring public sources (GitHub, Pastebin) for leaked/exposed AWS access keys
- Scanning for vulnerable GitLab instances and exploiting **CVE-2021-22205** (RCE) to harvest AWS credentials stored in code repositories
- At least one case involved discovering admin credentials in a leaked Terraform `.tfstate` file

## Signature Tooling
- **S3 Browser v9.5.5** — primary tool for IAM manipulation, S3 access, and general recon; leaves a distinctive `S3 Browser 9.5.5` CloudTrail `userAgent` string
- AWS Management Console, accessed directly via browser once console credentials are established

## Core TTPs
- Creates new IAM users with names mimicking the victim's own naming conventions (e.g. `sec_audit` modeled on an existing audit-role naming pattern, or `backup`)
- `iam:CreateAccessKey` on the new user to keep S3 Browser functional
- `iam:GetLoginProfile` — reconnaissance to identify existing users that **lack** console access
- `iam:CreateLoginProfile` — sets a console password on an **existing** user to stealthily inherit its permissions rather than creating an obviously-new admin (their most distinctive persistence move)
- `iam:PutUserPolicy` — attaches a fully permissive inline policy (effectively `*:*`)
- `ec2:CreateKeyPair` + `ec2:AuthorizeSecurityGroupIngress` (opening TCP/22 to `0.0.0.0/0`) for EC2 persistence; spreads across regions if instance limits are hit
- Actively monitors CloudTrail during incident response and adapts persistence tactics in response to defender action

## IOCs
- IPs: `182.1.229.252`, `114.125.247.101`, `114.125.245.53`, `36.85.110.142`
- ASNs: PT. Telekomunikasi Selula, PT Telekomunikasi Indonesia
- IAM usernames: `backup`, `sec_audit`
- Inline policy names: `sdgs`, `ter`, `dq`
- SSH key pair names: `su32`, `new-user-*`
- CloudTrail user agent: `S3 Browser 9.5.5`

## Detection Angle
Because GUI-Vil relies on manual GUI tooling rather than scripted automation, its activity clusters around human working hours (UTC/GMT aligned to Indonesian timezone) and leaves a consistent, identifiable user agent — a much stronger signal than typical scripted cloud attackers, most of whom blend into automation-tool user agents (`aws-cli`, `Boto3`, etc.).

## References
- [Unmasking GUI-vil: A Cloud Threat Actor Case Study — Permiso (p0 Labs)](https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor/)

## Related Notes
- [[GUI-Vil (p0-LUCR-1) AWS Cryptomining Campaigns - Research Extraction]] — full research extraction, including two related independent case studies (DataDog Security Labs, "XAV" persistence script)
- [[AWS IAM Privilege Escalation]] — TTP note covering the general technique this actor abuses
- [[Hunt - AWS IAM Privilege Escalation]] — active hunt hypothesis
- [[Research Index]]
