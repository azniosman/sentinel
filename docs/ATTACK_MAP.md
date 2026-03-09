# Cyber Attack Map

## Overview

The **Cyber Attack Map** is an interactive 3D visualization dashboard for monitoring global cyber threats in real-time. It displays attack origins, targets, threat actor activity, and provides AI-powered analysis for each detected incident.

![Attack Map Dashboard](./images/attack-map-overview.png)

---

## Features

### 🗺️ 3D Globe Visualization

- **Animated Attack Arcs**: Glowing lines showing attack paths from origin to target countries
- **Pulsing Nodes**: Visual indicators at attack origin and target locations
- **Auto-Rotation**: Slowly rotating globe for comprehensive viewing
- **Interactive Controls**: Click and drag to rotate, scroll to zoom

### 🎯 Attack Type Visualization

Each attack type has a unique color scheme:

| Attack Type | Color | Description |
|-------------|-------|-------------|
| **Ransomware** | 🔴 Red | Ransomware attacks targeting organizations |
| **DDoS** | 🟠 Orange | Distributed Denial of Service attacks |
| **Phishing** | 🟡 Yellow | Social engineering and credential harvesting |
| **Malware** | 🟣 Purple | Malicious software deployment |
| **Zero-Day** | 🔴 Dark Red | Previously unknown vulnerability exploits |
| **Credential Theft** | 🔵 Cyan | Password and authentication theft |

### 📊 Real-Time Statistics

Live dashboard showing:
- Total attacks detected
- Active attacks in progress
- Critical severity incidents
- Unique threat actors identified

### 🔍 Interactive Filters

Filter attacks by:
- **Attack Type**: Ransomware, DDoS, Phishing, Malware, Zero-Day, Credential Theft
- **Severity**: Critical, High, Medium, Low
- **Status**: Active, Investigating, Mitigated

### 🤖 AI-Powered Analysis

Click any attack arc to get:
- Detailed attack information
- Threat actor profile
- Malware family details
- Exploited CVE information
- **AI-generated analysis** with mitigation recommendations via RAG

### 📡 Live Attack Stream

Real-time feed showing:
- New attack detections
- Simulation events
- System notifications

### 🎮 Simulation Mode

Toggle simulation mode to:
- Generate realistic simulated attacks
- Demonstrate visualization capabilities
- Test system response
- Training and demonstration purposes

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Attack Map Frontend                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │  Globe.gl   │  │   Side      │  │    Control Panel        │ │
│  │  3D Visual  │  │   Panel     │  │    - Simulation Toggle  │ │
│  │  Arcs &     │  │   - Stats   │  │    - Filters            │ │
│  │  Points     │  │   - Details │  │    - Refresh/Clear      │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Backend API Layer                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  /api/attack_   │  │  /api/attack_   │  │  /api/attack_   │ │
│  │  events         │  │  events/stats   │  │  events/        │ │
│  │                 │  │                 │  │  simulate       │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Data Layer                                   │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  attack_events  │  │  country_       │  │  threat_        │ │
│  │  .json          │  │  coordinates    │  │  actors.json    │ │
│  │                 │  │  .json          │  │                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## API Endpoints

### Get Attack Events

```bash
GET /api/attack_events?limit=50&attack_type=&severity=&status=
```

**Parameters:**
- `limit` (1-200): Maximum events to return
- `attack_type`: Filter by type (ransomware, ddos, phishing, etc.)
- `severity`: Filter by severity (critical, high, medium, low)
- `status`: Filter by status (active, investigating, mitigated)

**Response:**
```json
{
  "status": "success",
  "events": [
    {
      "id": "attack_001",
      "origin_country": "Russia",
      "origin_country_code": "RU",
      "target_country": "United States",
      "target_country_code": "US",
      "attack_type": "ransomware",
      "threat_actor": "LockBit",
      "malware_family": "LockBit 3.0",
      "target_sector": "Finance",
      "cve_exploited": "CVE-2024-3400",
      "severity": "critical",
      "timestamp": "2026-03-09T08:15:00Z",
      "status": "active",
      "origin_lat": 61.5240,
      "origin_lng": 105.3188,
      "target_lat": 37.0902,
      "target_lng": -95.7129,
      "arc_color": "#ef4444",
      "arc_width": 2.0,
      "pulse_color": "#fca5a5"
    }
  ],
  "total": 12,
  "timestamp": "2026-03-09T10:00:00Z"
}
```

### Get Attack Statistics

```bash
GET /api/attack_events/stats
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "total_attacks": 50,
    "active_attacks": 25,
    "by_type": {
      "ransomware": 15,
      "ddos": 10,
      "phishing": 12,
      "malware": 8,
      "zero_day": 3,
      "credential_theft": 2
    },
    "by_severity": {
      "critical": 10,
      "high": 20,
      "medium": 15,
      "low": 5
    },
    "top_origins": [
      {"code": "RU", "count": 20},
      {"code": "CN", "count": 15},
      {"code": "IR", "count": 10}
    ],
    "top_targets": [
      {"code": "US", "count": 18},
      {"code": "GB", "count": 8},
      {"code": "DE", "count": 6}
    ],
    "top_actors": [
      {"name": "LockBit", "count": 10},
      {"name": "APT41", "count": 8},
      {"name": "Lazarus Group", "count": 6}
    ],
    "top_sectors": [
      {"name": "Finance", "count": 12},
      {"name": "Government", "count": 10},
      {"name": "Healthcare", "count": 8}
    ]
  },
  "timestamp": "2026-03-09T10:00:00Z"
}
```

### Simulate Attack Event

```bash
POST /api/attack_events/simulate
```

**Response:**
```json
{
  "status": "success",
  "event": {
    "id": "sim_20260309100000000000",
    "origin_country_code": "RU",
    "target_country_code": "US",
    "attack_type": "ransomware",
    "threat_actor": "LockBit",
    "malware_family": "LockBit 3.0",
    "target_sector": "Finance",
    "cve_exploited": "CVE-2024-3400",
    "severity": "critical",
    "timestamp": "2026-03-09T10:00:00Z",
    "status": "active",
    "simulated": true
  },
  "message": "Simulated attack event generated"
}
```

### Get Attack Heatmap

```bash
GET /api/attack_events/heatmap?grid_size=50
```

**Response:**
```json
{
  "status": "success",
  "heatmap": [
    {"lat": 37.0902, "lng": -95.7129, "intensity": 1.0},
    {"lat": 55.3781, "lng": -3.4360, "intensity": 0.8},
    {"lat": 51.1657, "lng": 10.4515, "intensity": 0.6}
  ],
  "grid_size": 50,
  "timestamp": "2026-03-09T10:00:00Z"
}
```

---

## Data Files

### Attack Events (`/data/threat_intel/attack_events.json`)

```json
{
  "attack_events": [
    {
      "id": "attack_001",
      "origin_country": "Russia",
      "origin_country_code": "RU",
      "target_country": "United States",
      "target_country_code": "US",
      "attack_type": "ransomware",
      "threat_actor": "LockBit",
      "malware_family": "LockBit 3.0",
      "target_sector": "Finance",
      "cve_exploited": "CVE-2024-3400",
      "severity": "critical",
      "timestamp": "2026-03-09T08:15:00Z",
      "status": "active"
    }
  ]
}
```

### Country Coordinates (`/data/threat_intel/country_coordinates.json`)

Contains latitude/longitude for all countries used in arc visualization.

---

## Simulation Engine

The built-in simulation engine generates realistic cyber attack scenarios:

### Attack Generation

- **Origin Countries**: Russia (35%), China (30%), Iran (15%), North Korea (12%), Others (8%)
- **Target Countries**: US (25%), UK (12%), Germany (10%), France (8%), Japan (8%), Others (37%)
- **Attack Types**: Ransomware (25%), DDoS (20%), Phishing (20%), Malware (15%), Zero-Day (10%), Credential Theft (10%)
- **Severity**: Critical (20%), High (35%), Medium (30%), Low (15%)

### Threat Actors by Origin

| Origin | Threat Actors |
|--------|---------------|
| Russia | LockBit, APT28, Sandworm, Killnet, APT29 |
| China | APT41, Volt Typhoon, RedEcho, APT10 |
| Iran | MuddyWater, OilRig, Charcoal Bank, APT33 |
| North Korea | Lazarus Group, Kimsuky, APT38 |

---

## Usage

### Access the Attack Map

1. Start the AI-SOC backend:
   ```bash
   cd backend
   python main.py
   ```

2. Open the Attack Map in your browser:
   ```
   http://localhost:3000/attack_map.html
   ```

### Controls

| Control | Action |
|---------|--------|
| **Left Click + Drag** | Rotate globe |
| **Scroll** | Zoom in/out |
| **Right Click + Drag** | Pan view |
| **Click Arc** | View attack details & AI analysis |
| **Simulation Toggle** | Enable/disable auto-generation |
| **Refresh** | Reload attack data |
| **Clear Arcs** | Remove all displayed attacks |
| **Burst Mode** | Generate 5 simulated attacks |

### Filters

Use the filter panel to narrow down displayed attacks:

1. **Attack Type**: Select specific attack category
2. **Severity**: Filter by threat level
3. **Status**: Show only active/mitigated/investigating

---

## Integration

### SOC Logs Integration

All attack events are logged to the SOC logging system:

```
[ATTACK_EVENT_DETECTED]
Origin: Russia → Target: United States
Type: Ransomware | Severity: CRITICAL
Threat Actor: LockBit
```

### RAG Integration

When clicking an attack arc, the system automatically queries the RAG engine:

```
Query: "Analyze this cyber attack: ransomware from Russia targeting 
United States's Finance sector. Threat actor: LockBit. CVE exploited: 
CVE-2024-3400. Provide attack explanation and mitigation recommendations."
```

Response includes:
- Attack vector explanation
- CVE details and impact
- Mitigation steps
- Detection recommendations

---

## Performance

- **Max Displayed Arcs**: 100 simultaneous attacks
- **Auto-Refresh**: Every 10 seconds
- **Arc Animation**: 2-second dash animation
- **Globe Rotation**: 0.5 RPM when idle

---

## Customization

### Adding New Attack Types

1. Update `ATTACK_TYPE_CONFIG` in `backend/attack_map/api.py`
2. Add color mapping in frontend `ATTACK_COLORS`
3. Update filter dropdown in `attack_map.html`

### Adding Threat Actors

Edit `backend/attack_map/simulation.py`:

```python
self.threat_actors = {
    "RU": [
        {"name": "NewActor", "malware": "NewMalware", "sectors": ["Finance"]},
        # ... existing actors
    ],
    # ... other origins
}
```

### Adjusting Simulation Frequency

```python
# In simulation.py
self.simulation_interval = 30  # seconds between attacks
```

---

## Troubleshooting

### Globe Not Loading

- Check internet connection (globe textures load from CDN)
- Verify WebGL support in browser
- Check browser console for errors

### No Attacks Displayed

- Verify backend is running on port 8000
- Check `/api/attack_events` endpoint returns data
- Ensure data files exist in `/data/threat_intel/`

### AI Analysis Not Working

- Verify Ollama is running
- Check RAG engine is initialized
- Verify embedding model is loaded

---

## Security Notes

- All attack data is **simulated or from local datasets**
- No external APIs are called for attack data
- Simulation mode is for **demonstration only**
- Real-world deployment should integrate with actual threat feeds

---

## Future Enhancements

- [ ] Real-time threat feed integration (MISP, OTX)
- [ ] Historical attack timeline view
- [ ] Sector-specific heatmaps
- [ ] Attack chain visualization
- [ ] Export attack reports (PDF, JSON)
- [ ] Multi-globe view for comparison
- [ ] VR/AR support for immersive analysis
