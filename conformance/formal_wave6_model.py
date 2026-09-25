#!/usr/bin/env python3
import hashlib,json
def d(v): return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(",",":")).encode()).hexdigest()
a={"operation_id":"publish_clip","method":"POST","path":"/clips/{id}/publish"}
b={"path":"/clips/{id}/publish","operation_id":"publish_clip","method":"POST"}
c={"operation_id":"publish_clip","method":"DELETE","path":"/clips/{id}/publish"}
assert d(a)==d(b)
assert d(a)!=d(c), "behavioral change preserved operation digest"
print("clip operation digest: ok")
