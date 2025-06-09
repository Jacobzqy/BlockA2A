import json

payload = {"b": 1, "a": 2}
payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
print(payload_json)

