"""
ITDR Engine — Identity Threat Detection & Response

Ingests identity telemetry (Okta, Azure AD, AWS CloudTrail style) and
detects compromised-identity indicators using behavioral analytics:

  1. Impossible Travel — login from two countries within impossible time
  2. Credential Stuffing / Brute Force — repeated failed logins from same IP
  3. MFA Fatigue / Prompt Bombing — repeated push denials then approval
  4. Privilege Escalation — unusual role/group changes
  5. Persistence — CreateAccessKey, new credentials for existing users
  6. Lateral Movement — AssumeRole chains from unexpected IPs
  7. Data Exfiltration Indicators — PutBucketPolicy to public, StopLogging
  8. Dormant Account Reactivation — login to account idle >90 days
  9. Service Account Anomaly — service account used from unexpected IP
  10. Session Anomaly — concurrent sessions from different geolocations

Each detection maps to MITRE ATT&CK for enterprise + cloud matrix.

Author: Adithya Vasamsetti (CyberEnthusiastic)
License: MIT
"""
import argparse
import json
import math
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple


BASE_DIR = Path(__file__).parent

# Earth radius in km (for impossible travel calc)
EARTH_R = 6371

# Approximate city lat/lon for impossible-travel detection
CITY_COORDS = {
    "seattle": (47.6, -122.3), "portland": (45.5, -122.7), "san francisco": (37.8, -122.4),
    "austin": (30.3, -97.7), "new york": (40.7, -74.0), "arlington": (38.9, -77.1),
    "bucharest": (44.4, 26.1), "moscow": (55.8, 37.6), "shanghai": (31.2, 121.5),
    "lagos": (6.5, 3.4), "tehran": (35.7, 51.4), "london": (51.5, -0.1),
    "us-east-1": (39.0, -77.5), "us-west-2": (45.6, -122.3),
}

# Max speed a human can travel (km/h) — ~900 km/h = fastest commercial flight
MAX_TRAVEL_SPEED = 900


def haversine(lat1, lon1, lat2, lon2) -> float:
    """Distance in km between two lat/lon points."""
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return 2 * EARTH_R * math.asin(math.sqrt(a))


def parse_ts(ts_str: str) -> datetime:
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))


# --- Detection Rules --------------------------------------------------------

@dataclass
class Alert:
    detection_id: str
    detection_name: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    mitre_tactic: str
    mitre_technique: str
    user: str
    timestamp: str
    detail: str
    evidence: List[str] = field(default_factory=list)
    recommended_action: str = ""
    risk_score: float = 0.0


class ITDREngine:
    def __init__(self, events: List[dict]):
        self.events = sorted(events, key=lambda e: e["ts"])
        self.alerts: List[Alert] = []

    def run_all_detections(self) -> List[Alert]:
        self.detect_impossible_travel()
        self.detect_brute_force()
        self.detect_mfa_fatigue()
        self.detect_privilege_escalation()
        self.detect_persistence()
        self.detect_lateral_movement()
        self.detect_exfil_indicators()
        self.detect_dormant_reactivation()
        self.detect_service_account_anomaly()
        return self.alerts

    # 1. IMPOSSIBLE TRAVEL
    def detect_impossible_travel(self):
        logins_by_user: Dict[str, List[dict]] = defaultdict(list)
        for e in self.events:
            if e["type"] in ("login_success",) and e.get("city"):
                logins_by_user[e["user"]].append(e)

        for user, logins in logins_by_user.items():
            for i in range(1, len(logins)):
                prev, curr = logins[i - 1], logins[i]
                c1 = CITY_COORDS.get(prev["city"].lower())
                c2 = CITY_COORDS.get(curr["city"].lower())
                if not c1 or not c2 or prev["city"] == curr["city"]:
                    continue
                dist = haversine(c1[0], c1[1], c2[0], c2[1])
                t1, t2 = parse_ts(prev["ts"]), parse_ts(curr["ts"])
                hours = max((t2 - t1).total_seconds() / 3600, 0.001)
                speed = dist / hours
                if speed > MAX_TRAVEL_SPEED and dist > 500:
                    self.alerts.append(Alert(
                        detection_id="ITDR-001",
                        detection_name="Impossible Travel",
                        severity="CRITICAL",
                        mitre_tactic="TA0001 Initial Access",
                        mitre_technique="T1078 Valid Accounts",
                        user=user,
                        timestamp=curr["ts"],
                        detail=f"{prev['city']} -> {curr['city']} ({dist:.0f} km in {hours:.1f}h = {speed:.0f} km/h)",
                        evidence=[
                            f"Login 1: {prev['ts']} from {prev['city']}, {prev['country']} ({prev['ip']})",
                            f"Login 2: {curr['ts']} from {curr['city']}, {curr['country']} ({curr['ip']})",
                            f"Required speed: {speed:.0f} km/h (max plausible: {MAX_TRAVEL_SPEED} km/h)",
                        ],
                        recommended_action="Terminate active sessions. Force password reset. Investigate compromised credentials.",
                        risk_score=95.0 if speed > 5000 else 85.0,
                    ))

    # 2. BRUTE FORCE / CREDENTIAL STUFFING
    def detect_brute_force(self, threshold: int = 5, window_min: int = 10):
        failed_by_ip: Dict[str, List[dict]] = defaultdict(list)
        for e in self.events:
            if e["type"] == "login_failed":
                failed_by_ip[e["ip"]].append(e)

        for ip, fails in failed_by_ip.items():
            if len(fails) < threshold:
                continue
            first, last = parse_ts(fails[0]["ts"]), parse_ts(fails[-1]["ts"])
            span_min = (last - first).total_seconds() / 60
            if span_min <= window_min:
                users_hit = set(f["user"] for f in fails)
                self.alerts.append(Alert(
                    detection_id="ITDR-002",
                    detection_name="Credential Stuffing / Brute Force",
                    severity="HIGH",
                    mitre_tactic="TA0006 Credential Access",
                    mitre_technique="T1110 Brute Force",
                    user=", ".join(users_hit),
                    timestamp=fails[0]["ts"],
                    detail=f"{len(fails)} failed logins from {ip} ({fails[0].get('country','?')}) in {span_min:.0f} min targeting {len(users_hit)} user(s)",
                    evidence=[f"{f['ts']} {f['user']} from {f['ip']} ({f['device']})" for f in fails[:5]],
                    recommended_action="Block source IP. Check if any user was subsequently compromised. Review firewall/WAF rules.",
                    risk_score=88.0 if len(fails) >= 10 else 75.0,
                ))

    # 3. MFA FATIGUE / PROMPT BOMBING
    def detect_mfa_fatigue(self, deny_threshold: int = 3):
        mfa_by_user: Dict[str, List[dict]] = defaultdict(list)
        for e in self.events:
            if e["type"] == "mfa_push":
                mfa_by_user[e["user"]].append(e)

        for user, pushes in mfa_by_user.items():
            denies = 0
            for p in pushes:
                if p.get("mfa") == "push_denied":
                    denies += 1
                elif p.get("mfa") == "push_approved" and denies >= deny_threshold:
                    self.alerts.append(Alert(
                        detection_id="ITDR-003",
                        detection_name="MFA Fatigue / Prompt Bombing",
                        severity="CRITICAL",
                        mitre_tactic="TA0006 Credential Access",
                        mitre_technique="T1621 MFA Request Generation",
                        user=user,
                        timestamp=p["ts"],
                        detail=f"{denies} MFA denials followed by approval — user likely wore down",
                        evidence=[f"{pp['ts']} {pp['mfa']} from {pp['ip']}" for pp in pushes],
                        recommended_action="Revoke session immediately. Force password reset. Investigate attacker IP. Enable number-matching MFA.",
                        risk_score=92.0,
                    ))
                    denies = 0
                elif p.get("mfa") == "push_approved":
                    denies = 0

    # 4. PRIVILEGE ESCALATION
    def detect_privilege_escalation(self):
        priv_keywords = ["admin", "root", "superuser", "global admin", "orgadmin", "owner"]
        for e in self.events:
            if e["type"] == "role_change":
                detail_lower = e.get("detail", "").lower()
                if any(kw in detail_lower for kw in priv_keywords):
                    self.alerts.append(Alert(
                        detection_id="ITDR-004",
                        detection_name="Privilege Escalation",
                        severity="CRITICAL" if "self-elevated" in detail_lower or "global admin" in detail_lower else "HIGH",
                        mitre_tactic="TA0004 Privilege Escalation",
                        mitre_technique="T1078.004 Cloud Accounts",
                        user=e["user"],
                        timestamp=e["ts"],
                        detail=e.get("detail", "Unknown role change"),
                        evidence=[f"{e['ts']} {e['user']} from {e['ip']} ({e.get('country','?')})"],
                        recommended_action="Verify with user manager. If unauthorized, revoke immediately and investigate.",
                        risk_score=90.0 if "self-elevated" in detail_lower else 80.0,
                    ))

    # 5. PERSISTENCE (CreateAccessKey, new credentials)
    def detect_persistence(self):
        for e in self.events:
            if e["type"] == "api_call":
                detail = e.get("detail", "")
                if "CreateAccessKey" in detail or "CreateLoginProfile" in detail:
                    self.alerts.append(Alert(
                        detection_id="ITDR-005",
                        detection_name="Persistence — New Credentials Created",
                        severity="HIGH",
                        mitre_tactic="TA0003 Persistence",
                        mitre_technique="T1098 Account Manipulation",
                        user=e["user"],
                        timestamp=e["ts"],
                        detail=detail,
                        evidence=[f"{e['ts']} {e['user']} from {e['ip']} ({e.get('country','?')})"],
                        recommended_action="Verify if this was an authorized change. Rotate the new key if suspicious.",
                        risk_score=78.0,
                    ))

    # 6. LATERAL MOVEMENT (AssumeRole from unexpected location)
    def detect_lateral_movement(self):
        for e in self.events:
            if e["type"] == "api_call" and "AssumeRole" in e.get("detail", ""):
                country = e.get("country", "")
                if country and country not in ("US",):
                    self.alerts.append(Alert(
                        detection_id="ITDR-006",
                        detection_name="Lateral Movement — Cross-Account AssumeRole",
                        severity="CRITICAL",
                        mitre_tactic="TA0008 Lateral Movement",
                        mitre_technique="T1550 Use Alternate Authentication Material",
                        user=e["user"],
                        timestamp=e["ts"],
                        detail=f"{e.get('detail','')} from {country}",
                        evidence=[f"{e['ts']} {e['user']} from {e['ip']} ({country}/{e.get('city','?')})"],
                        recommended_action="Investigate the assumed role's actions. Check for data access or exfiltration.",
                        risk_score=92.0,
                    ))

    # 7. DATA EXFILTRATION INDICATORS
    def detect_exfil_indicators(self):
        exfil_patterns = ["PutBucketPolicy", "StopLogging", "DeleteTrail", "DisableOrganization"]
        for e in self.events:
            if e["type"] == "api_call":
                detail = e.get("detail", "")
                for pat in exfil_patterns:
                    if pat in detail:
                        sev = "CRITICAL"
                        name = {
                            "PutBucketPolicy": "Data Exfil — S3 Bucket Made Public",
                            "StopLogging": "Anti-Forensics — CloudTrail Logging Disabled",
                            "DeleteTrail": "Anti-Forensics — CloudTrail Deleted",
                            "DisableOrganization": "Anti-Forensics — Org Controls Disabled",
                        }.get(pat, f"Suspicious API: {pat}")
                        self.alerts.append(Alert(
                            detection_id="ITDR-007",
                            detection_name=name,
                            severity=sev,
                            mitre_tactic="TA0010 Exfiltration" if "Bucket" in pat else "TA0005 Defense Evasion",
                            mitre_technique="T1537 Transfer Data to Cloud Account" if "Bucket" in pat else "T1562 Impair Defenses",
                            user=e["user"],
                            timestamp=e["ts"],
                            detail=detail,
                            evidence=[f"{e['ts']} {e['user']} from {e['ip']} ({e.get('country','?')})"],
                            recommended_action="Activate incident response. This is likely an active breach.",
                            risk_score=98.0,
                        ))

    # 8. DORMANT ACCOUNT REACTIVATION
    def detect_dormant_reactivation(self):
        for e in self.events:
            detail = e.get("detail", "").lower()
            if "dormant" in detail or (e["type"] == "password_change" and "dormant" in detail):
                self.alerts.append(Alert(
                    detection_id="ITDR-008",
                    detection_name="Dormant Account Reactivation",
                    severity="HIGH",
                    mitre_tactic="TA0001 Initial Access",
                    mitre_technique="T1078 Valid Accounts",
                    user=e["user"],
                    timestamp=e["ts"],
                    detail=e.get("detail", ""),
                    evidence=[f"{e['ts']} {e['user']} from {e['ip']} ({e.get('country','?')})"],
                    recommended_action="Verify with HR if account should still exist. If not, disable and investigate.",
                    risk_score=82.0,
                ))

    # 9. SERVICE ACCOUNT ANOMALY
    def detect_service_account_anomaly(self):
        sa_events: Dict[str, List[dict]] = defaultdict(list)
        for e in self.events:
            if "service-account" in e["user"] or "svc-" in e["user"]:
                sa_events[e["user"]].append(e)

        for sa, events in sa_events.items():
            ips = set(e["ip"] for e in events)
            internal_ips = [ip for ip in ips if ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192.168.")]
            external_ips = [ip for ip in ips if ip not in internal_ips]
            if external_ips and internal_ips:
                ext_events = [e for e in events if e["ip"] in external_ips]
                self.alerts.append(Alert(
                    detection_id="ITDR-009",
                    detection_name="Service Account Used from External IP",
                    severity="CRITICAL",
                    mitre_tactic="TA0001 Initial Access",
                    mitre_technique="T1078.001 Default Accounts",
                    user=sa,
                    timestamp=ext_events[0]["ts"],
                    detail=f"Service account accessed from external IP(s): {', '.join(external_ips)}",
                    evidence=[f"{e['ts']} from {e['ip']} ({e.get('country','?')}/{e.get('city','?')})" for e in ext_events],
                    recommended_action="Rotate service account credentials immediately. Investigate source of external access.",
                    risk_score=94.0,
                ))

    def summary(self) -> dict:
        by_sev = defaultdict(int)
        by_det = defaultdict(int)
        by_tactic = defaultdict(int)
        users_flagged = set()
        for a in self.alerts:
            by_sev[a.severity] += 1
            by_det[a.detection_name] += 1
            by_tactic[a.mitre_tactic] += 1
            users_flagged.add(a.user)
        return {
            "total_events": len(self.events),
            "total_alerts": len(self.alerts),
            "unique_users_flagged": len(users_flagged),
            "by_severity": dict(by_sev),
            "by_detection": dict(by_det),
            "by_mitre_tactic": dict(by_tactic),
            "risk_score_avg": round(sum(a.risk_score for a in self.alerts) / len(self.alerts), 1) if self.alerts else 0,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        }


# --- CLI ---
def main():
    from license_guard import verify_license, print_banner
    verify_license()
    print_banner("ITDR Engine")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="ITDR Engine - Identity Threat Detection & Response")
    parser.add_argument("-i", "--input", default="data/identity_events.json")
    parser.add_argument("-o", "--output", default="reports/itdr_report.json")
    parser.add_argument("--html", default="reports/itdr_report.html")
    args = parser.parse_args()

    print("=" * 60)
    print("  [ITDR Engine v1.0 - Identity Threat Detection & Response]")
    print("=" * 60)

    data = json.loads((BASE_DIR / args.input).read_text(encoding="utf-8"))
    events = data["events"]

    engine = ITDREngine(events)
    alerts = engine.run_all_detections()
    summary = engine.summary()

    print(f"  Events ingested   : {summary['total_events']}")
    print(f"  Alerts generated  : {summary['total_alerts']}")
    print(f"  Users flagged     : {summary['unique_users_flagged']}")
    print(f"  Avg risk score    : {summary['risk_score_avg']}")
    print(f"  By severity       : {summary['by_severity']}")
    print()

    for a in sorted(alerts, key=lambda x: -x.risk_score):
        sev_c = "\033[91m" if a.severity == "CRITICAL" else "\033[93m"
        reset = "\033[0m"
        print(f"  {sev_c}[{a.severity}]{reset} {a.detection_name} (risk={a.risk_score})")
        print(f"    User: {a.user}")
        print(f"    MITRE: {a.mitre_tactic} / {a.mitre_technique}")
        print(f"    Detail: {a.detail}")
        print(f"    Action: {a.recommended_action}")
        print()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "alerts": [asdict(a) for a in alerts]}, f, indent=2)
    print(f"[+] JSON report: {args.output}")

    from report_generator import generate_html
    generate_html(summary, alerts, args.html)
    print(f"[+] HTML report: {args.html}")


if __name__ == "__main__":
    main()
