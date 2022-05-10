from api import DynatraceAPIClient
import json

def acquire_alert(tenant:str, token_path:str, alert_id:str):
    with open(token_path) as f:
        token = f.readlines()[0].strip()

    client = DynatraceAPIClient.from_tenant_url(tenant, token)
    alert = client.acquire_extension_alert(alert_id)
    alert_name = alert["name"]

    json_alert = json.dumps(alert, indent=4)
    with open(f"./{alert_name}.json", 'w') as f:
        f.write(json_alert)