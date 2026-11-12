"""Turn one CloudTrail record into a small, flat event the methods can use."""
from datetime import datetime, timezone

def _ts(s):
    if not s:
        return None
    return datetime.strptime(s.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z").timestamp()

def net24(ip):
    parts = (ip or "").split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3]) + ".0/24"
    return ip or "-"           # AWS service names such as "s3.amazonaws.com"

def ua_family(ua):
    ua = (ua or "-").strip()
    for tag in ("aws-cli", "Boto3", "boto3", "Botocore", "curl", "python-requests", "aws-sdk-go", "aws-sdk-java", "console.amazonaws.com", "Mozilla"):
        if tag.lower() in ua.lower():
            return tag.lower()
    return ua.split("/")[0].split(" ")[0][:30].lower() or "-"

def _resources(r):
    out = [x.get("ARN") for x in r.get("resources") or [] if x.get("ARN")]
    rp = r.get("requestParameters") or {}
    if r.get("eventSource") == "s3.amazonaws.com" and rp.get("bucketName"):
        b = rp["bucketName"]
        out.append(f"arn:aws:s3:::{b}/{rp['key']}" if rp.get("key") else f"arn:aws:s3:::{b}")
    return sorted(set(out))

def normalize(r):
    """r is a CloudTrail record (the `detail` of an EventBridge event)."""
    ui = r.get("userIdentity") or {}
    sc = ui.get("sessionContext") or {}
    issuer = (sc.get("sessionIssuer") or {})
    attrs = sc.get("attributes") or {}
    if ui.get("type") == "AssumedRole":
        identity = issuer.get("userName") or ui.get("arn", "?").split("/")[-2]
    elif ui.get("type") == "IAMUser":
        identity = ui.get("userName") or ui.get("arn", "?").split("/")[-1]
    elif ui.get("type") == "Root":
        identity = "root"
    else:
        identity = ui.get("invokedBy") or ui.get("type") or "?"
    resp = r.get("responseElements") or {}
    creds = resp.get("credentials") if isinstance(resp, dict) else None
    rp = r.get("requestParameters") or {}
    src = (r.get("eventSource") or "").replace(".amazonaws.com", "")
    return {
        "id": r.get("eventID"),
        "t": _ts(r.get("eventTime")),
        "time": r.get("eventTime"),
        "identity": identity,
        "itype": ui.get("type"),
        "arn": ui.get("arn"),
        "key": ui.get("accessKeyId"),
        "issuer": issuer.get("arn"),
        "created": _ts(attrs.get("creationDate")),
        "ip": r.get("sourceIPAddress"),
        "net": net24(r.get("sourceIPAddress")),
        "ua": r.get("userAgent"),
        "uaf": ua_family(r.get("userAgent")),
        "region": r.get("awsRegion"),
        "source": src,
        "name": r.get("eventName"),
        "token": f"{src}:{r.get('eventName')}",
        "error": r.get("errorCode"),
        "read_only": r.get("readOnly"),
        "resources": _resources(r),
        "issued_key": (creds or {}).get("accessKeyId") if creds else None,
        "assumed_role": rp.get("roleArn") if r.get("eventName", "").startswith("AssumeRole") else None,
        "service_event": ui.get("type") == "AWSService" or bool(ui.get("invokedBy")),
    }
