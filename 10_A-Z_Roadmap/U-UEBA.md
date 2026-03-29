# U — User and Entity Behavior Analytics (UEBA)

## Beginner Explanation
UEBA uses machine learning and statistical analysis to build a baseline of normal behavior for each user and system, then alerts when behavior deviates significantly. Instead of alerting on every failed login, UEBA notices that a user who normally logs in from New York at 9am is suddenly logging in from Romania at 3am and accessing systems they've never touched before.

## Technical Deep Dive

### What UEBA Monitors
| Entity | Behavioral Signals |
|--------|-------------------|
| **Users** | Login times, geographic locations, data access volume, applications used |
| **Service Accounts** | Typical access patterns, systems accessed, query volume |
| **Endpoints** | Process behavior, network connections, file access patterns |
| **Network Devices** | Traffic baselines, protocol anomalies |

### UEBA Use Cases
1. **Compromised Credentials:** User logging in from impossible geographies (New York and London 10 minutes apart)
2. **Insider Threat:** Employee accessing 10x their normal data volume in final days before resignation
3. **Lateral Movement:** Service account suddenly authenticating to systems it has never accessed
4. **Data Exfiltration:** Large outbound transfer to personal cloud storage outside business hours
5. **Privilege Escalation:** User account accessing resources normally only accessed by administrators

### Impossible Travel Detection (Example Logic)
```python
from math import radians, sin, cos, sqrt, atan2

def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
    return R * 2 * atan2(sqrt(a), sqrt(1-a))

def check_impossible_travel(logins):
    for i in range(1, len(logins)):
        prev, curr = logins[i-1], logins[i]
        dist_km = haversine_km(prev["lat"], prev["lon"], curr["lat"], curr["lon"])
        time_hrs = (curr["timestamp"] - prev["timestamp"]).total_seconds() / 3600
        max_speed = 900  # km/h (commercial aircraft)
        if time_hrs > 0 and dist_km / time_hrs > max_speed:
            print(f"IMPOSSIBLE TRAVEL: {dist_km:.0f}km in {time_hrs:.1f}hrs for {curr['user']}")
```

### UEBA Platforms
| Platform | Deployment |
|----------|-----------|
| Microsoft Sentinel (built-in UEBA) | Cloud (Azure) |
| Splunk UBA | On-premise / Cloud |
| Securonix | Cloud |
| Exabeam | Cloud |
| Elastic SIEM (ML Jobs) | On-premise / Cloud |

### Elastic ML Anomaly Detection Example
```json
{
  "analysis_config": {
    "bucket_span": "15m",
    "detectors": [{
      "detector_description": "Unusual login hour for user",
      "function": "time_of_day",
      "by_field_name": "user.name"
    }]
  }
}
```

## Real-World Relevance
**Uber Breach (2022):** An attacker compromised a contractor's credentials via MFA fatigue. UEBA would have flagged: new device, unusual time, immediate access to sensitive admin systems — behavior completely outside the contractor's baseline. Existing alerts weren't tuned to catch this specific behavioral deviation.

## Defensive Measures
1. Enable UEBA in your SIEM (Microsoft Sentinel, Splunk UBA, Elastic ML)
2. Tune baselines per user role — executives, developers, and service accounts have different normal behaviors
3. Alert on impossible travel, first-time-seen access, and significant data volume anomalies
4. Review high-risk UEBA alerts daily — treat like EDR alerts, not routine noise
5. Integrate UEBA alerts with SOAR for automated initial response (disable account, require re-auth)

## Practice Challenge
1. Write a Python function that detects if a user has accessed more than 3× their 30-day average file count in a single day.
2. Design a UEBA use case for detecting a compromised service account (what baseline metrics would you track?).
3. Review your SIEM for any existing behavioral analytics rules — are they enabled and tuned?
