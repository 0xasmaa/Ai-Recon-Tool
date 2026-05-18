# AI Recon Tool

An automated reconnaissance tool that combines subdomain enumeration, live host detection, vulnerability scanning, and AI-powered analysis  all in one command.

---

![Tool Demo](images/video1.png)

![Tool Demo](images/Screenshoot.png)



## What It Does

```
subfinder  →  finds all subdomains
httpx      →  checks which ones are alive + detects technologies
nuclei     →  scans for vulnerabilities
AI         →  analyzes results and ranks by risk level
report     →  saves everything to a markdown file
```

---

## Requirements

### Tools (must be installed separately)
| Tool | Install |
| :--- | :--- |
| subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

> Make sure Go is installed and `~/go/bin` is in your PATH:
> ```bash
> export PATH=$PATH:~/go/bin
> echo 'export PATH=$PATH:~/go/bin' >> ~/.zshrc
> source ~/.zshrc
> ```

### Python Dependencies
```bash
pip install requests rich
```

### API Key
This tool uses [Groq](https://console.groq.com) for AI analysis — it's free.

1. Go to [console.groq.com](https://console.groq.com)
2. Sign up
3. Click **API Keys** → **Create API Key**
4. Copy your key

---

## Installation

```bash
# clone the repo
git clone https://github.com/0xasmaa/ai-recon.git
cd ai-recon

# install python dependencies
pip install requests rich

# update nuclei templates
nuclei -update-templates
```

---

## Usage

```bash
python3 tool.py --target example.com --api-key YOUR_GROQ_KEY
```

### Arguments

| Argument | Required | Description |
| :--- | :--- | :--- |
| `--target` | ✅ Yes | Target domain to scan |
| `--api-key` | ✅ Yes | Your Groq API key |

---

## Output

The tool generates a markdown report saved as `domain_report.md`:

```
example.com_report.md
```

### Report includes:
- **Summary Metrics** — total subdomains, alive hosts, vulnerabilities
- **Alive Subdomains Table** — URL, status code, detected technologies
- **Raw Nuclei Output** — all vulnerability findings
- **AI Security Analysis** — risk ranking and recommended next steps

---

## Example Output

```
[*] Scanning: example.com
[+] Found 47 subdomains
[*] Checking alive subdomains...
[+] Found 23 alive subdomains
[*] Scanning for vulnerabilities...
[*] Scanning: https://admin.example.com
[!] Found 2 issues
[+] Clean: https://mail.example.com
[*] Sending to AI for analysis...
[+] AI Analysis Complete.
[+] All results compiled into example.com_report.md
```

---

## How It Works

```
1. subfinder finds all subdomains for the target domain
2. httpx checks which are alive and detects technologies
3. nuclei scans each alive subdomain for vulnerabilities
4. results are sent to Groq AI for analysis and risk ranking
5. everything saved to a markdown report
```

---

## Disclaimer

> This tool is intended for **authorized security testing only**.
> Only use it on domains you own or have explicit permission to test.
> The author is not responsible for any misuse.

---

## 0xasmaa

Built from scratch as a learning project to understand how recon tools work and how AI fits into security workflows.
