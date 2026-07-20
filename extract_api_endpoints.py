#!/usr/bin/env python3
"""
extract_api_endpoints.py

Two techniques to map hidden API surface that plain crawling/wayback misses:

1. OpenAPI/Swagger spec discovery — probes common doc paths on every live
   host; if a response is valid JSON containing a "paths" key (the OpenAPI/
   Swagger structure), every documented endpoint + HTTP method is extracted.
   This is standard published API documentation, not an exploit — we're just
   reading it.

2. GraphQL introspection — sends the standard, publicly-documented GraphQL
   introspection query (a normal, read-only GraphQL query; this is how every
   GraphQL client, including browser devtools, discovers a schema) to common
   GraphQL paths. If introspection is enabled, every query/mutation/
   subscription field is listed. Note: introspection being enabled on a
   production endpoint is itself often worth flagging — it shouldn't usually
   be open publicly.

Reads:  live/httpx_live.txt
Writes: report/api_endpoints.json
        report/api_endpoints.txt

Usage: run from WORKDIR root
    python3 extract_api_endpoints.py

Requires: requests (pip install requests --break-system-packages)
"""
import os
import json
import concurrent.futures

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("  ⚠ 'requests' not installed — skipping API extraction.")
    print("    pip install requests --break-system-packages")
    raise SystemExit(0)

TIMEOUT = 8
MAX_WORKERS = 15
MAX_ENDPOINTS_PER_SPEC = 500
MAX_OPS_PER_SCHEMA = 300

API_DOC_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/v1/swagger.json", "/v2/swagger.json",
    "/v2/api-docs", "/v3/api-docs", "/openapi.json", "/api/swagger.json",
    "/api-docs", "/api-docs.json", "/api/openapi.json", "/swagger-ui/swagger.json",
    "/.well-known/openapi.json", "/openapi.yaml",
]

GRAPHQL_PATHS = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query"]

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args { name }
      }
    }
  }
}
"""

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}


def read_hosts(path="live/httpx_live.txt"):
    hosts = []
    if not os.path.isfile(path):
        return hosts
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            url = line.split()[0]
            if url.startswith("http"):
                hosts.append(url.rstrip("/"))
    return sorted(set(hosts))


def try_parse_openapi(host):
    for path in API_DOC_PATHS:
        url = host + path
        try:
            r = requests.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        try:
            spec = r.json()
        except Exception:
            continue
        if not isinstance(spec, dict) or "paths" not in spec:
            continue

        base_path = spec.get("basePath", "")
        endpoints = []
        for ep_path, methods in spec.get("paths", {}).items():
            if not isinstance(methods, dict):
                continue
            for method in methods.keys():
                if method.lower() in HTTP_METHODS:
                    endpoints.append({"method": method.upper(), "path": base_path + ep_path})
                if len(endpoints) >= MAX_ENDPOINTS_PER_SPEC:
                    break
            if len(endpoints) >= MAX_ENDPOINTS_PER_SPEC:
                break

        return {
            "host": host,
            "spec_url": url,
            "title": (spec.get("info") or {}).get("title", ""),
            "version": (spec.get("info") or {}).get("version", ""),
            "endpoint_count": len(endpoints),
            "endpoints": endpoints,
        }
    return None


def try_graphql_introspection(host):
    for path in GRAPHQL_PATHS:
        url = host + path
        try:
            r = requests.post(url, json={"query": INTROSPECTION_QUERY}, timeout=TIMEOUT, verify=False)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        schema = (data or {}).get("data", {}).get("__schema")
        if not schema:
            continue

        types_by_name = {t["name"]: t for t in schema.get("types", []) if t.get("name")}

        def fields_of(type_name):
            t = types_by_name.get(type_name)
            if not t:
                return []
            out = []
            for f in (t.get("fields") or [])[:MAX_OPS_PER_SCHEMA]:
                args = [a["name"] for a in (f.get("args") or [])]
                out.append({"name": f["name"], "args": args})
            return out

        query_type = (schema.get("queryType") or {}).get("name")
        mutation_type = (schema.get("mutationType") or {}).get("name")
        subscription_type = (schema.get("subscriptionType") or {}).get("name")

        return {
            "host": host,
            "endpoint_url": url,
            "introspection_enabled": True,
            "queries": fields_of(query_type) if query_type else [],
            "mutations": fields_of(mutation_type) if mutation_type else [],
            "subscriptions": fields_of(subscription_type) if subscription_type else [],
        }
    return None


def scan_host(host):
    return try_parse_openapi(host), try_graphql_introspection(host)


def main():
    hosts = read_hosts()
    openapi_specs = []
    graphql_endpoints = []

    if hosts:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            for i, (spec, gql) in enumerate(ex.map(scan_host, hosts), 1):
                if spec:
                    openapi_specs.append(spec)
                if gql:
                    graphql_endpoints.append(gql)
                print(f"\r  probing hosts for API specs (swagger/graphql)  {i}/{len(hosts)}   ", end="", flush=True)
    print("")

    os.makedirs("report", exist_ok=True)
    summary = {
        "hosts_scanned": len(hosts),
        "openapi_specs_found": len(openapi_specs),
        "graphql_introspection_enabled": len(graphql_endpoints),
        "openapi_specs": openapi_specs,
        "graphql_endpoints": graphql_endpoints,
    }
    with open("report/api_endpoints.json", "w") as f:
        json.dump(summary, f, indent=2)

    total_rest_endpoints = sum(s["endpoint_count"] for s in openapi_specs)

    with open("report/api_endpoints.txt", "w") as f:
        f.write(f"Hosts scanned: {len(hosts)}\n")
        f.write(f"OpenAPI/Swagger specs found: {len(openapi_specs)} ({total_rest_endpoints} total documented endpoints)\n")
        f.write(f"GraphQL endpoints with introspection ENABLED: {len(graphql_endpoints)}\n\n")

        if openapi_specs:
            f.write("=== OPENAPI / SWAGGER SPECS ===\n")
            for s in openapi_specs:
                f.write(f"\n[{s['host']}] spec: {s['spec_url']}  (title: {s['title'] or '?'}, {s['endpoint_count']} endpoints)\n")
                for e in s["endpoints"][:100]:
                    f.write(f"    {e['method']:6s} {e['path']}\n")
                if s["endpoint_count"] > 100:
                    f.write(f"    ... and {s['endpoint_count']-100} more (see api_endpoints.json)\n")
            f.write("\n")

        if graphql_endpoints:
            f.write("=== GRAPHQL — INTROSPECTION ENABLED (worth flagging on its own) ===\n")
            for g in graphql_endpoints:
                f.write(f"\n[{g['host']}] endpoint: {g['endpoint_url']}\n")
                f.write(f"    queries ({len(g['queries'])}): {', '.join(q['name'] for q in g['queries'][:40])}\n")
                f.write(f"    mutations ({len(g['mutations'])}): {', '.join(m['name'] for m in g['mutations'][:40])}\n")
                if g["subscriptions"]:
                    f.write(f"    subscriptions ({len(g['subscriptions'])}): {', '.join(s['name'] for s in g['subscriptions'][:40])}\n")

    print(f"  ✓ API extraction: {len(openapi_specs)} OpenAPI specs ({total_rest_endpoints} endpoints), "
          f"{len(graphql_endpoints)} GraphQL introspection-enabled -> report/api_endpoints.*")


if __name__ == "__main__":
    main()
