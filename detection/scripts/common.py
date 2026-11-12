import configparser, json, pathlib
import boto3
ROOT = pathlib.Path(__file__).resolve().parent.parent
CFG = json.loads((ROOT / "config.json").read_text())
REGION = CFG["region"]

def alice_session():
    c = configparser.ConfigParser(); c.read(ROOT / "data" / "demo_credentials.ini")
    a = c["pw25-dev-alice"]
    return boto3.Session(aws_access_key_id=a["aws_access_key_id"], aws_secret_access_key=a["aws_secret_access_key"], region_name=REGION)

def decoy_session():
    c = configparser.ConfigParser(); c.read(ROOT / "data" / "demo_credentials.ini")
    a = c["pw25-decoy"]
    return boto3.Session(aws_access_key_id=a["aws_access_key_id"], aws_secret_access_key=a["aws_secret_access_key"], region_name=REGION)

def assume(session, role_arn, name, config=None):
    sts = session.client("sts", region_name=REGION, config=config, endpoint_url=f"https://sts.{REGION}.amazonaws.com")
    c = sts.assume_role(RoleArn=role_arn, RoleSessionName=name, DurationSeconds=3600)["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"], region_name=REGION), c["AccessKeyId"]
