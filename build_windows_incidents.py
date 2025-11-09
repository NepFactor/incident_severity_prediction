import csv
import re
from datetime import datetime, timedelta
from collections import defaultdict

INPUT_FILE = "windows-security.txt"
OUTPUT_FILE = "windows_incidents.csv"

# Lines of 5+ dashes separate events
EVENT_SEPARATOR_REGEX = re.compile(r"^-{5,}$")

SUSPICIOUS_PROCESSES = [
    "pypykatz",
    "mimikatz",
    "procdump",
    "xintent",
    "sekurlsa",
]

SUSPICIOUS_UTILITY_HINTS = [
    "esentutl",
    "reg.exe",
    "reg ",
    "regsave",
]

SENSITIVE_HIVE_HINTS = [
    "sam",
    "security",
    "system",
    "hklm\\sam",
    "hklm\\security",
    "hklm\\system",
]

ADMIN_GROUP_KEYWORDS = [
    "administrators",
    "backup operators",
    "domain admins",
    "enterprise admins",
]

PRIVILEGE_KEYWORDS = [
    "sebackupprivilege",
    "serestoreprivilege",
    "sedebugprivilege",
    "seimpersonateprivilege",
    "setcbprivilege",
    "seassignprimarytokenprivilege",
]

DAY_START_HOUR = 8
DAY_END_HOUR = 18


def split_events(lines):
    events = []
    current = []
    for line in lines:
        if EVENT_SEPARATOR_REGEX.match(line.strip()):
            if current:
                events.append(current)
                current = []
        else:
            if line.strip() or current:
                current.append(line.rstrip("\n"))
    if current:
        events.append(current)
    return events


def parse_kv_pairs(event_lines):
    """
    Turn an event block into a dict.
    - Detect bare datetime line.
    - Parse key=value and key: value pairs.
    - Everything else goes into _raw.
    """
    data = {}
    for line in event_lines:
        s = line.strip()
        if not s:
            continue

        # Bare datetime line like: 03/12/2021 10:48:47 AM
        if re.match(r"^\d{2}/\d{2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M$", s):
            data["DateTimeLine"] = s
            continue

        if "=" in line:
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if key:
                data[key] = val
                continue

        if ":" in line:
            key, val = line.split(":", 1)
            # Only treat as key: value if key looks label-ish
            if key.strip() and len(key.strip().split()) <= 4:
                data[key.strip()] = val.strip()
                continue

        data.setdefault("_raw", "")
        data["_raw"] += " " + s

    return data


def extract_timestamp(fields):
    # Prefer explicit DateTimeLine
    dt = fields.get("DateTimeLine")
    if dt:
        try:
            return datetime.strptime(dt, "%m/%d/%Y %I:%M:%S %p")
        except ValueError:
            pass

    # Fallback: search in _raw
    raw = fields.get("_raw", "")
    m = re.search(
        r"(\d{2}/\d{2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)", raw
    )
    if m:
        try:
            return datetime.strptime(m.group(1), "%m/%d/%Y %I:%M:%S %p")
        except ValueError:
            pass

    return None


def extract_event_id(fields):
    # Check common keys, including EventCode from your logs
    for key in ["EventID", "Event Id", "Event ID", "Id", "EventCode"]:
        if key in fields:
            m = re.search(r"\d+", fields[key])
            if m:
                return int(m.group(0))

    # Fallback search in _raw
    raw = fields.get("_raw", "")
    m = re.search(r"(Event(ID|Code)?)[:=\s]+(\d+)", raw, re.IGNORECASE)
    if m:
        return int(m.group(3))

    return None


def extract_account(fields):
    for key in [
        "Account Name",
        "SubjectUserName",
        "TargetUserName",
        "Security ID",
        "SubjectSecurityId",
    ]:
        if key in fields and fields[key]:
            return fields[key]
    return None


def extract_process_name(fields):
    for key in [
        "New Process Name",
        "Process Name",
        "Image",
        "Executable",
        "Application",
    ]:
        if key in fields and fields[key]:
            val = fields[key].replace("\\", "/").strip()
            if "/" in val:
                val = val.split("/")[-1]
            return val.lower()

    raw = fields.get("_raw", "").lower()
    m = re.search(r"([\w\-]+\.exe)", raw)
    if m:
        return m.group(1)
    return None


def extract_group_name(fields):
    for key in ["Group Name", "Security Group", "Group"]:
        if key in fields and fields[key]:
            return fields[key]

    raw = fields.get("_raw", "")
    m = re.search(r"Group Name[:\s]+(.+)", raw, re.IGNORECASE)
    if m:
        return m.group(1).strip()

    return None


def is_privileged_logon(event_id, fields):
    raw = (fields.get("_raw", "") + " " +
           " ".join(f"{k}={v}" for k, v in fields.items())).lower()

    if event_id in (4672,):
        return 1

    if any(p in raw for p in PRIVILEGE_KEYWORDS):
        return 1

    acct = (extract_account(fields) or "").lower()
    if any(x in acct for x in ["\\system", "administrator"]):
        return 1

    return 0


def touches_admin_group(fields):
    group = (extract_group_name(fields) or "").lower()
    raw = (fields.get("_raw", "")).lower()

    if any(g in group for g in ADMIN_GROUP_KEYWORDS):
        return 1
    if any(g in raw for g in ADMIN_GROUP_KEYWORDS):
        return 1

    return 0


def is_suspicious_process(process_name, fields):
    raw = (fields.get("_raw", "")).lower()

    if process_name:
        pn = process_name.lower()
        if any(sp in pn for sp in SUSPICIOUS_PROCESSES):
            return 1
        if any(h in raw for h in SENSITIVE_HIVE_HINTS) and any(
            u in pn for u in SUSPICIOUS_UTILITY_HINTS
        ):
            return 1

    if any(sp in raw for sp in SUSPICIOUS_PROCESSES):
        return 1
    if any(h in raw for h in SENSITIVE_HIVE_HINTS) and any(
        u in raw for u in SUSPICIOUS_UTILITY_HINTS
    ):
        return 1

    return 0


def get_time_bucket(ts):
    if ts is None:
        return "unknown"
    if DAY_START_HOUR <= ts.hour < DAY_END_HOUR:
        return "day"
    return "night"


def compute_burst_counts(records, window_minutes=5):
    """
    burst_count = # of events with same (account,event_id)
    within +/- window_minutes of this event.
    """
    if not records:
        return

    by_key = defaultdict(list)
    for idx, rec in enumerate(records):
        key = (rec.get("account"), rec.get("event_id"))
        by_key[key].append(idx)

    window = timedelta(minutes=window_minutes)

    for key, idx_list in by_key.items():
        times = [records[i]["timestamp"] for i in idx_list]
        left = 0
        for right in range(len(idx_list)):
            t_right = times[right]
            if t_right is None:
                records[idx_list[right]]["burst_count"] = 1
                continue
            while left < right and times[left] and times[left] < t_right - window:
                left += 1
            # count events in window [t_right - window, t_right]
            count = 0
            for k in range(left, right + 1):
                if times[k] and abs((times[k] - t_right)) <= window:
                    count += 1
            records[idx_list[right]]["burst_count"] = max(count, 1)


def main():
    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    events = split_events(lines)

    records = []
    for ev in events:
        fields = parse_kv_pairs(ev)

        ts = extract_timestamp(fields)
        event_id = extract_event_id(fields)
        account = extract_account(fields)
        process_name = extract_process_name(fields)
        group_name = extract_group_name(fields)

        privileged = is_privileged_logon(event_id, fields) if event_id else 0
        admin_touch = touches_admin_group(fields)
        suspicious = is_suspicious_process(process_name, fields)
        time_bucket = get_time_bucket(ts)

        records.append({
            "timestamp": ts,
            "event_id": event_id,
            "account": account,
            "process_name": process_name,
            "group_name": group_name,
            "privileged_logon": privileged,
            "admin_group_touch": admin_touch,
            "suspicious_process": suspicious,
            "time_bucket": time_bucket,
            "burst_count": 1,
        })

    # sort + compute burst counts
    records.sort(key=lambda r: (r["timestamp"] is None, r["timestamp"]))
    compute_burst_counts(records, window_minutes=5)

    # write CSV
    fieldnames = [
        "timestamp",
        "event_id",
        "account",
        "process_name",
        "group_name",
        "privileged_logon",
        "admin_group_touch",
        "suspicious_process",
        "time_bucket",
        "burst_count",
    ]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=fieldnames)
        w.writeheader()
        for r in records:
            row = r.copy()
            if isinstance(row["timestamp"], datetime):
                row["timestamp"] = row["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            else:
                row["timestamp"] = ""
            w.writerow(row)

    print(f"Wrote {len(records)} rows to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

