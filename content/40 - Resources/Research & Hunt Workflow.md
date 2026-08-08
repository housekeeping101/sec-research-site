# Research & Hunt Workflow

A repeatable process for turning raw threat intelligence into structured knowledge, actionable hunts, and searchable reference material.

---

## The Workflow

```
SOURCE (article / blog / report / tweet)
    │
    ▼
[1] RESEARCH EXTRACTION NOTE        → Malware & TTPs/
    Raw technical dump: file paths,
    tools, commands, IOCs, API endpoints
    │
    ▼
[2] TTP NOTE                        → Attack Techniques/
    Structured technique: MITRE mapping,
    how it works, detection opportunities,
    query stubs
    │
    ▼
[3] HUNT HYPOTHESIS                 → 20 - Areas/Threat Hunting/
    Actionable hunt: hypothesis statement,
    hunt plan, queries, findings, outcome
    │
    ▼
[4] UPDATE INDEX + DAILY NOTE + CHANGELOG
    Research Index → Research Index.md
    Daily Note     → 00 - Inbox/Daily Note/YYYY-MM-DD.md
    Changelog      → CHANGELOG.md
```

---

## Note Types & Destinations

| Note Type | Template | Destination | Purpose |
|---|---|---|---|
| Research Extraction | Template - TTP Note | `Malware & TTPs/` | Raw technical intel dump |
| TTP Note | Template - TTP Note | `Attack Techniques/` | Structured MITRE-mapped technique |
| Hunt Hypothesis | Template - Hunt Hypothesis | `20 - Areas/Threat Hunting/` | Actionable hunt with queries and findings |
| Threat Actor Profile | Template - Threat Actor Profile | `Threat Actors & APTs/` | Actor attribution and TTP mapping |
| IOC Tracker | Template - IOC Tracker | `40 - Resources/Indicators (IOCs)/` | Campaign-specific indicators |
| Reading Note | Template - Reading Note | `30 - Knowledge/Books & Reading Notes/` | Long-form content (books, papers, reports) |

---

## Step-by-Step

### Step 1 — Research Extraction
**Goal:** Capture everything useful from the source before analysis.

Extract and document:
- All relevant file paths (Windows and macOS where applicable)
- Tools used by the attacker and their purpose
- Commands or code snippets referenced
- API endpoints, registry keys, environment variables
- IOCs if present (hashes, IPs, domains)
- Vendor response or patch status
- Attacker stealth / anti-forensic notes

**Name:** `[Topic] - Research Extraction.md`
**Link to:** TTP note, Hunt Hypothesis (add once created)

---

### Step 2 — TTP Note
**Goal:** Formalize the technique with structure that supports detection engineering.

Include:
- MITRE ATT&CK tactic and technique ID(s)
- How the technique works (step-by-step)
- Detection opportunities: log sources, behavioral indicators, artifacts
- Query stubs (CrowdStrike FQL, Databricks SQL)
- Threat actor usage if known
- References

**Name:** `[Technique Name].md`
**Link to:** Research Extraction note, Hunt Hypothesis

---

### Step 3 — Hunt Hypothesis
**Goal:** Translate the TTP into an executable hunt with a clear hypothesis and actionable queries.

Structure:
- Hypothesis statement: *"I believe [behavior] is occurring because [reason], which would manifest as [observable]"*
- Assumptions and scope (environment, timeframe, data sources)
- Numbered hunt plan
- Ready-to-run queries (CrowdStrike FQL + Databricks SQL)
- Findings section (complete after running)
- Outcome checkbox (closed / escalated / detection created)

**Name:** `Hunt - [Topic].md`
**Link to:** TTP note, Research Extraction, related hunts

---

### Step 4 — Update Index and Admin Notes
After creating all notes:
1. Add entries to `[[Research Index]]` under the relevant category
2. Add a one-line entry to today's daily note with `[[links]]` to all created notes
3. Add entries to `CHANGELOG.md`

---

## Naming Conventions

| Type | Format | Example |
|---|---|---|
| Research Extraction | `[Topic] - Research Extraction.md` | `Slack Session Hijacking - Research Extraction.md` |
| TTP Note | `[Technique or Tool Name].md` | `Abusing Slack for Offensive Operations.md` |
| Hunt Hypothesis | `Hunt - [Topic].md` | `Hunt - Slack Cookie Theft and Session Hijacking.md` |
| Threat Actor | `[Actor Name].md` | `Scattered Spider.md` |
| IOC Tracker | `IOC - [Campaign].md` | `IOC - CrateDepression.md` |

---

## Linking Rules
- Every note links **forward** (to what it produced) and **backward** (to what produced it)
- Research Extraction → links to TTP Note + Hunt Hypothesis
- TTP Note → links to Research Extraction + Hunt Hypothesis
- Hunt Hypothesis → links to TTP Note + Research Extraction + Query Library
- All notes → link to `[[Research Index]]` category section

---

## Automating This Workflow

Three Claude Code slash commands support this system:

| Command | Purpose |
|---|---|
| `/hunt-research <url>` | Full automation — fetch a source, create all three linked notes, update index, daily note, and CHANGELOG |
| `/vault-organize <path>` | Migrate an existing note collection (Obsidian, Notion, Roam, etc.) into this folder structure |
| `/vault-setup <path>` | Bootstrap folder structure, templates, and infrastructure on a fresh or existing vault |

**Usage:**
```
/hunt-research https://example.com/blog/some-technique
/vault-organize /path/to/old-vault
/vault-setup /path/to/new-vault
```

---

## Query Library

Every Hunt that produces a stable, reusable query should have a corresponding entry in the query library.

### When to Create a Library Entry

Create a library entry when:
- A Hunt note contains a query you've run and validated (status `stable`)
- The query is parameterizable (timeframe, identity, threshold, etc.)
- You want it discoverable via MITRE technique, tag, or platform search

### Naming Convention

| Platform | Prefix | Example |
|---|---|---|
| CrowdStrike FQL | `cs-` | `cs-hunt-slack-cookie-theft.md` |
| Databricks SQL | `db-` | `db-hunt-iam-privesc.md` |
| Multi-platform | `multi-` | `multi-hunt-credential-access.md` |

Hunt queries additionally include `hunt` in the slug. Place files in `40 - Resources/Query Library/queries/hunting/`.

### Linking Back to the Hunt Note

After creating the library file, add a reference line in the Hunt note immediately after the query section header:

```
> Parameterized: `40 - Resources/Query Library/queries/hunting/cs-hunt-<slug>.md`
```

### How to Render a Query

Fill in Jinja2 parameters and print the rendered query to stdout:

```bash
python "40 - Resources/Scripts/render.py" "40 - Resources/Query Library/queries/hunting/cs-hunt-slack-cookie-theft.md" --params timeframe=7d
```

Override multiple params:

```bash
python "40 - Resources/Scripts/render.py" "40 - Resources/Query Library/queries/hunting/db-hunt-iam-privesc.md" \
  --params timeframe=30d
```

### How to Search the Library

Search by MITRE technique, platform, category, tag, or status:

```bash
python "40 - Resources/Scripts/search.py" --mitre T1539
python "40 - Resources/Scripts/search.py" --platform crowdstrike_fql --category hunting
python "40 - Resources/Scripts/search.py" --tag lateral-movement
python "40 - Resources/Scripts/search.py" --status stable
```

### Validate Before Committing

Run locally before opening a PR — CI runs the same check:

```bash
python "40 - Resources/Scripts/validate.py"
```

---

## Related Notes
- [[Research Index]]
- [[40 - Resources/Templates/Template - TTP Note]]
- [[40 - Resources/Templates/Template - Hunt Hypothesis]]
- [[40 - Resources/Templates/Template - Threat Actor Profile]]
- [[40 - Resources/Templates/Template - IOC Tracker]]
- [[40 - Resources/Query Library/Hunt Queries]]
