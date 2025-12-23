# Automated Web Recon & Vulnerability Analysis Framework

An end-to-end **automated web reconnaissance and analysis pipeline** built for real-world bug bounty and security testing workflows.

This project focuses on **scaling recon**, **reducing noise**, and **prioritizing what actually matters**, using scripting + Docker + n8n + AI-assisted analysis.

## Core Idea

Manual recon doesn’t scale. Tools produce noise.
This framework **chains recon, analysis, and visualization into one repeatable pipeline** so you can focus on exploitation, not babysitting tools.

**High-level goals:**

* Automate recon aggressively
* Extract and normalize attack surface
* Use AI to triage large JS/code datasets
* Run focused bypass & traversal tests
* Produce a clear, reviewable output

## Features

* Subdomain enumeration and categorization
* Directory brute-forcing
* JavaScript discovery and deduplication
* AI-assisted JavaScript sensitivity analysis
* 403 bypass testing
* Path traversal probing
* Structured output storage
* Final visualization using Mermaid mind maps

## Architecture Overview

```
Target Domain
   |
   v
Subdomain Enumeration
   |
   v
HTTP Status Categorization (200 / 403 / 404 / others)
   |
   v
Directory Enumeration
   |
   v
JavaScript Extraction
   |
   v
Normalization & Deduplication
   |
   v
n8n Webhook → AI Analysis
   |
   v
Suspicious Asset Storage
   |
   v
403 Bypass & Path Traversal Modules
   |
   v
Mermaid Visualization
```

## Requirements

### System

* Linux (tested on Ubuntu-based systems)
* Bash
* Docker & Docker Compose

### Tools (installed locally)

* `subfinder`
* `httpx`
* `ffuf` / `dirsearch` (depending on config)
* `jq`
* `curl`

### Services

* Dockerized **n8n**
* GEMINI API key (or compatible LLM endpoint)

## Directory Structure

```
.
├── main.sh                # Entry point
├── subdomains.sh          # Subdomain enumeration & filtering
├── dirs.sh                # Directory enumeration
├── js/                    # JS extraction & processing
├── output/
│   ├── subdomains/
│   ├── directories/
│   ├── js/
│   ├── ai_analysis/
│   └── reports/
├── docker-compose.yml     # n8n setup
└── README.md
```


## Setup

### 1. Clone the repository

```bash
git clone <repo-url>
cd <repo-name>
```

### 2. Start Docker & n8n

```bash
docker compose up -d
```

Ensure n8n is accessible on:

```
http://localhost:5678
```

### 3. Configure n8n

* Create a webhook workflow
* Set output directory permissions
* Configure OpenAI (or LLM) credentials
* Map incoming JS URLs → AI analysis → JSON output

> If n8n cannot write files, **fix volume permissions** before proceeding.

## Usage

### Run the full pipeline

```bash
bash main.sh <target-domain>
```

### What `main.sh` does

1. Creates required directory structure
2. Runs subdomain enumeration
3. Categorizes subdomains by HTTP status
4. Launches directory enumeration
5. Extracts JS URLs from:

   * HTML responses
   * `robots.txt`
   * `sitemap.xml`
6. Normalizes and deduplicates JS files
7. Sends JS URLs to n8n in batches
8. Receives AI-evaluated JSON responses
9. Stores suspicious JS assets
10. Runs:

    * 403 bypass techniques
    * Path traversal probes
11. Generates a Mermaid-based visualization

## Output

* **Raw recon data** (subdomains, dirs, JS)
* **AI-triaged JS findings**
* **403 bypass results**
* **Traversal probe results**
* **Final mind map** for manual review

Everything is stored locally and versionable.

## Why AI Is Used Here

* Triage large JS files
* Identify sensitive keywords, endpoints, tokens, patterns
* Reduce human scanning time
* Prioritize what deserves manual testing

You still exploit manually.

## Limitations

* Not a scanner
* Not exploit automation
* Requires manual review and thinking
* Depends on tool accuracy and target response behavior

## Intended Audience

* Bug bounty hunters
* AppSec students
* Red teamers building personal tooling
* Anyone who wants **control over recon**, not black boxes

