# Data Directory

This directory stores all AI-SOC data files including threat intelligence datasets and raw feeds.

## Directory Structure

```
data/
├── raw_feeds/          # Raw downloaded threat feeds
│   └── .gitkeep
└── threat_intel/       # Processed threat intelligence
    └── .gitkeep
```

## Data Types

### Raw Feeds (`raw_feeds/`)

Temporary storage for downloaded threat intelligence feeds:

- NVD CVE JSON feeds
- MITRE ATT&CK STIX data
- CISA Known Exploited Vulnerabilities
- Security advisory RSS feeds

These files are processed and then may be archived or deleted.

### Threat Intelligence (`threat_intel/`)

Processed and structured threat intelligence data:

- `cves.json` - CVE vulnerability database with CVSS scores
- `zero_days.json` - Zero-day vulnerability alerts
- `threat_actors.json` - APT and criminal group profiles
- `malware_families.json` - Malware classifications
- `ioc_database.json` - Indicators of Compromise
- `mitre_attack.json` - MITRE ATT&CK framework data
- `security_advisories.json` - Vendor/CERT advisories

## Data Retention

- **CVE Data**: Updated every 6 hours, retains last 90 days
- **Zero-Day Alerts**: Persistent until manually archived
- **Threat Actors**: Persistent, updated weekly
- **IOC Database**: Persistent, updated continuously
- **MITRE ATT&CK**: Updated monthly

## Backup Recommendations

For production deployments:

```bash
# Backup threat intelligence data
tar -czf threat_intel_backup_$(date +%Y%m%d).tar.gz data/threat_intel/

# Backup vector store
tar -czf vector_store_backup_$(date +%Y%m%d).tar.gz vector_store/chroma_db/
```

## Manual Data Import

To import custom threat intelligence:

1. Format data according to schemas in `backend/threat_ingestion/schema.py`
2. Place JSON files in `data/threat_intel/`
3. Restart backend service to load new data

## Data Privacy

- All data is stored locally
- No cloud synchronization
- Optional encryption at rest (see `ENCRYPT_DATA_AT_REST` in config)
- Regular backups recommended
