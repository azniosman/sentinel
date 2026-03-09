# Real-Time Activity Log System

## Overview

The **Activity Log System** provides comprehensive observability for the AI-SOC platform, capturing every major system event, pipeline execution, agent activity, and security detection in real-time.

![Activity Log Dashboard](./images/activity-log-overview.png)

---

## Features

### 📊 Real-Time Event Streaming

- **WebSocket-based** live event feed
- **Sub-second latency** for event delivery
- **Automatic reconnection** on disconnect
- **Pause/Resume** functionality

### 🏷️ Event Categories

| Category | Color | Description |
|----------|-------|-------------|
| **SYSTEM** | 🔵 Blue | Core system operations |
| **RAG_PIPELINE** | 🔷 Cyan | RAG query execution stages |
| **AI_AGENT** | 🟣 Purple | AI agent activities |
| **NETWORK_ANALYSIS** | 🟢 Green | Network scan events |
| **THREAT_INTELLIGENCE** | 🟡 Yellow | Threat feed ingestion |
| **VULNERABILITY_DETECTION** | 🟠 Orange | Vulnerability detections |
| **ATTACK_MAP** | 🔴 Red | Attack map events |
| **DATASET_UPDATE** | 🔹 Teal | Dataset updates |
| **USER_QUERY** | 🟪 Purple | User interactions |
| **SECURITY_ALERT** | 🚨 Red | Security alerts |
| **SCHEDULER** | ⚫ Gray | Scheduled tasks |
| **IOC_CORRELATION** | 🩷 Pink | IOC correlation events |
| **ATTACK_SIMULATION** | 🌹 Rose | Simulation events |

### 🔍 Filtering & Search

Filter events by:
- **Category** - Event type category
- **Severity** - debug, info, warning, error, critical
- **Module** - Source module name
- **Search Query** - Full-text search in messages and metadata

### 📥 Export Functionality

Export logs in multiple formats:
- **JSON** - Structured data export
- **CSV** - Spreadsheet-compatible format

### ⏱️ Activity Timeline

Visual timeline showing:
- Recent activity bursts
- Event frequency
- System activity patterns

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Activity Log Frontend                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  Log Feed   │  │   Filters   │  │    Activity Timeline    │ │
│  │  - Live     │  │   - Category│  │    - Recent Events      │ │
│  │  - Scroll   │  │   - Severity│  │    - Event Frequency    │ │
│  │  - Search   │  │   - Module  │  │    - Activity Bursts    │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Activity Log API                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  REST Endpoints │  │  WebSocket      │  │  Export         │ │
│  │  - /activity_   │  │  - /ws/activity │  │  - JSON/CSV     │ │
│  │    stream       │  │  - Real-time    │  │  - Download     │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Activity Logger                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  Event Buffer   │  │  File Storage   │  │  Subscribers    │ │
│  │  - 1000 events  │  │  - JSON logs    │  │  - WebSocket    │ │
│  │  - Circular     │  │  - 30 day       │  │  - Callbacks    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Event Structure

Each activity event follows a structured format:

```json
{
  "id": "evt_001",
  "timestamp": "2026-03-09T12:45:10.123Z",
  "category": "RAG_PIPELINE",
  "event_type": "VECTOR_SEARCH_COMPLETED",
  "module": "rag_engine",
  "message": "Vector search completed in 7.97ms",
  "severity": "info",
  "metadata": {
    "query": "latest critical CVEs",
    "results_count": 5,
    "latency_ms": 7.97
  },
  "color": "#06b6d4"
}
```

---

## API Endpoints

### Get Activity Events

```bash
GET /api/activity_stream?limit=100&category=RAG_PIPELINE&severity=info
```

**Parameters:**
- `limit` (1-1000): Maximum events to return
- `category`: Filter by category
- `severity`: Filter by severity level
- `module`: Filter by module name
- `search`: Search query in message and metadata
- `start_time`: Filter events after ISO timestamp
- `end_time`: Filter events before ISO timestamp

**Response:**
```json
{
  "status": "success",
  "events": [...],
  "total": 100,
  "timestamp": "2026-03-09T12:45:10Z"
}
```

### Get Activity Statistics

```bash
GET /api/activity_stats
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "total_events": 1500,
    "by_category": {
      "RAG_PIPELINE": 500,
      "AI_AGENT": 300,
      "NETWORK_ANALYSIS": 200
    },
    "by_severity": {
      "info": 1200,
      "warning": 200,
      "error": 100
    },
    "security_alerts": 50,
    "recent_activity_1h": 150
  },
  "timestamp": "2026-03-09T12:45:10Z"
}
```

### Get Event Categories

```bash
GET /api/activity_categories
```

**Response:**
```json
{
  "status": "success",
  "categories": [
    {"name": "SYSTEM", "color": "#3b82f6"},
    {"name": "RAG_PIPELINE", "color": "#06b6d4"},
    ...
  ],
  "severities": ["debug", "info", "warning", "error", "critical"],
  "timestamp": "2026-03-09T12:45:10Z"
}
```

### Export Activity Logs

```bash
GET /api/activity_export?format=json&start_time=2026-03-01T00:00:00Z
```

**Parameters:**
- `format`: `json` or `csv`
- `start_time`: Export events after this time
- `end_time`: Export events before this time

### WebSocket Streaming

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/activity');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('New event:', data);
};
```

---

## Logged Events by Module

### RAG Pipeline

| Event Type | Description | Metadata |
|------------|-------------|----------|
| `RAG_QUERY_RECEIVED` | Query received | query, top_k |
| `EMBEDDING_GENERATED` | Embedding created | query, model |
| `VECTOR_SEARCH_STARTED` | Search initiated | query |
| `VECTOR_SEARCH_COMPLETED` | Search completed | results_count, latency_ms |
| `CONTEXT_BUILT` | Context assembled | context_length |
| `LLM_QUERY_STARTED` | LLM query sent | model |
| `LLM_RESPONSE_RECEIVED` | LLM response | response_length |
| `RAG_QUERY_COMPLETED` | Query finished | total_latency_ms |
| `RAG_QUERY_FAILED` | Query failed | error |

### AI Agents

| Event Type | Description |
|------------|-------------|
| `AGENT_TRIGGERED` | Agent execution started |
| `AGENT_COMPLETED` | Agent execution finished |
| `AGENT_ERROR` | Agent execution failed |
| `THREAT_HUNTER_SCAN` | Threat hunting scan |
| `VULNERABILITY_ANALYSIS` | Vulnerability analysis |
| `NETWORK_MONITOR_ALERT` | Network anomaly detected |

### Network Analysis

| Event Type | Description | Metadata |
|------------|-------------|----------|
| `NETWORK_SCAN_STARTED` | Scan initiated | targets |
| `NETWORK_SCAN_COMPLETED` | Scan finished | hosts_found |
| `OPEN_PORT_DETECTED` | Port found | host, port, service |
| `VULNERABLE_SERVICE_FOUND` | Vulnerability matched | host, cve |

### Threat Intelligence

| Event Type | Description | Metadata |
|------------|-------------|----------|
| `CVE_FEED_UPDATED` | CVE feed refreshed | records_count |
| `THREAT_INTEL_INGESTED` | Intelligence processed | source |
| `ZERO_DAY_DETECTED` | Zero-day identified | cve_id, risk_score |

### Attack Map

| Event Type | Description | Metadata |
|------------|-------------|----------|
| `ATTACK_EVENT_DETECTED` | Attack detected | origin, target, type |
| `SIMULATION_STARTED` | Simulation enabled |
| `SIMULATION_EVENT` | Simulated attack | attack_data |

### Security Alerts

| Event Type | Description | Severity |
|------------|-------------|----------|
| `ZERO_DAY_ALERT` | Zero-day vulnerability | critical |
| `CRITICAL_VULNERABILITY` | Critical CVE detected | critical |
| `SUSPICIOUS_ACTIVITY` | Anomalous behavior | high |
| `IOC_MATCH` | IOC correlation match | varies |

---

## Usage

### Access the Activity Log

1. **Direct Access**: http://localhost:3000/activity_log.html
2. **From Dashboard**: Click "📋 Activity Log" navigation button

### Filter Events

1. Select **Category** from dropdown
2. Select **Severity** level
3. Enter **Search** query
4. Enter **Module** name

### Export Logs

1. Click "📥 Export" button
2. Choose format (JSON/CSV)
3. Download file

### Pause/Resume

1. Click "⏸️ Pause" to stop live updates
2. Click "▶️ Resume" to resume

---

## Integration Guide

### Logging from Your Module

```python
from observability.activity_logger import log_event, EventCategory, SeverityLevel

# Log an event
log_event(
    category=EventCategory.YOUR_MODULE,
    event_type="YOUR_EVENT_TYPE",
    module="your_module_name",
    message="Human-readable message",
    severity=SeverityLevel.INFO,
    metadata={"key": "value"},
)

# Log an error
log_event(
    category=EventCategory.SYSTEM,
    event_type="ERROR",
    module="your_module",
    message="Something went wrong",
    severity=SeverityLevel.ERROR,
    metadata={"error": str(exception)},
)

# Log a security alert
log_event(
    category=EventCategory.SECURITY_ALERT,
    event_type="CRITICAL_ISSUE",
    module="security_monitor",
    message="Critical security issue detected",
    severity=SeverityLevel.CRITICAL,
    metadata={"details": "..."},
)
```

### Event Category Best Practices

1. **Use specific categories** - Don't log everything as SYSTEM
2. **Include relevant metadata** - Add context for debugging
3. **Use appropriate severity** - Don't overuse error/critical
4. **Keep messages concise** - Clear and informative

---

## Log Storage

### Location

```
/data/logs/
├── activity_log.json      # All events (append-only)
└── security_alerts.json   # Security alerts only
```

### Retention

- **Default**: 30 days
- **Memory buffer**: Last 1000 events
- **Cleanup**: Automatic via API endpoint

### Export

```bash
# Export last 24 hours as JSON
curl "http://localhost:8000/api/activity_export?format=json&start_time=$(date -d '24 hours ago' -Iseconds)"

# Export as CSV
curl "http://localhost:8000/api/activity_export?format=csv"
```

---

## Performance

### Specifications

| Metric | Value |
|--------|-------|
| Memory Buffer | 1000 events |
| WebSocket Latency | <100ms |
| File I/O | Append-only |
| Max Export | 10000 events |

### Optimization

- Circular buffer prevents memory growth
- Async WebSocket broadcasting
- Batch file writes
- Automatic cleanup of old events

---

## Troubleshooting

### No Events Showing

1. Check backend is running
2. Verify WebSocket connection
3. Check `/api/activity_stream` endpoint

### WebSocket Disconnects

- Automatic reconnection every 3 seconds
- Check network connectivity
- Verify no firewall blocking

### Export Fails

- Check log files exist in `/data/logs/`
- Verify sufficient disk space
- Check file permissions

---

## Security Considerations

- **No sensitive data** in logs (API keys, passwords)
- **Access control** recommended for production
- **Log rotation** for long-term deployments
- **Export encryption** for sensitive environments

---

## Future Enhancements

- [ ] Log aggregation from multiple instances
- [ ] Advanced analytics dashboard
- [ ] Anomaly detection on log patterns
- [ ] Integration with external SIEM
- [ ] Custom alert rules
- [ ] Log compression for long-term storage
