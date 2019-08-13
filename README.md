# isDomainSpoofable
Checks the status of SPF and DMARC for a domain

**Python version:**
- Python3

# Requirements:
    pip install -r requirements.txt

# Usage:
    python isDomainSpoofable.py

Script reads domains from domains.yaml and parses spf and dmarc records, if they exist.
Result is written to "result.csv".

# Example csv output:
    Entity,Domain,Has SPF,Has DMARC,DMARC p Policy,SPF record,DMARC record
    Example Entity,example.com,Yes,No,,v=spf1 -all,
    Microsoft,microsoft.com,Yes,Yes,reject,v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com include:_spf-c.microsoft.com include:_spf-ssg-a.microsoft.com include:spf-a.hotmail.com ip4:147.243.128.24 ip4:147.243.128.26 ip4:147.243.1.153 ip4:147.243.1.47 ip4:147.243.1.48 -all,v=DMARC1; p=reject; pct=100; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com; fo=1
    Google,google.com,Yes,Yes,reject,v=spf1 include:_spf.google.com ~all,v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com
