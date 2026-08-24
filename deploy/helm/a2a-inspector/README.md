# a2a-inspector Helm chart

Deploys the A2A Protocol Inspector as a single Deployment, Service and Ingress.
The container is one process: a FastAPI + Socket.IO app under uvicorn on port
8080 that also serves the built frontend, so there is no separate web server
and no sidecar.

## Install

```sh
helm upgrade --install a2a-inspector deploy/helm/a2a-inspector \
  --namespace a2a-inspector --create-namespace \
  --set image.tag=sha-abc1234 \
  --set ingress.host=a2a-inspector.example.internal
```

On the data-muc cluster this chart is not installed by hand: the ArgoCD
`Application` at `data-muc/demo-apps/a2a-inspector.yaml` in the `argocd`
repository points at this directory and pins `image.tag`.

## Security: this app is unauthenticated and will fetch any URL you give it

`POST /agent-card` and the `initialize_client` Socket.IO event take an
arbitrary user-supplied URL plus arbitrary user-supplied headers and have the
**server** fetch it. There is no allowlist, no scheme or host restriction, and
nothing blocking RFC1918 ranges or the cloud metadata endpoint at
`169.254.169.254`.

Anyone who can reach the ingress can therefore use the pod as an SSRF pivot
into the cluster network. The chart ships no auth layer, so the only thing
protecting it is the hostname being internal. Keep it on an internal domain.

If it ever needs to go somewhere more exposed, front it with a Traefik
`basicAuth` Middleware (the pattern `metabase` and `longhorn-ui` use on this
cluster) or an oauth2-proxy, and add an egress `NetworkPolicy` that denies
RFC1918 and link-local destinations.

## Why `replicaCount` is 1

`backend/app.py` holds a module-level `clients` dict keyed by Socket.IO session
id, containing a live `httpx.AsyncClient` per connected browser. The
`POST /agent-card` handler emits its debug log back to that session id, so the
HTTP request must land on the same pod that holds the WebSocket.

With two replicas the app does not crash — the debug console just silently
stops receiving events for roughly half of all requests. Scaling out requires
adding a Socket.IO Redis manager to the application first; sticky sessions
alone are not enough, because the `/agent-card` POST is a separate connection.

For the same reason the Deployment uses `strategy: Recreate`: a rolling surge
would briefly run two pods.

## Values worth knowing

| Key | Default | Notes |
| --- | --- | --- |
| `image.tag` | `""` | Falls back to `.Chart.AppVersion`. Pin a `sha-` tag in production. |
| `imagePullSecrets` | `[]` | GHCR packages are private unless published; the data-muc deployment sets `github-registry` here. |
| `service.port` / `service.targetPort` | `80` / `8080` | The container listens on 8080. |
| `ingress.host` | `a2a-inspector.data.mayflower.zone` | |
| `securityContext.readOnlyRootFilesystem` | `true` | Works because the chart mounts an `emptyDir` at `/tmp` and the image sets `HOME=/tmp`. |
| `startupProbe.failureThreshold` | `30` | Importing `a2a-sdk[all]` pulls grpc and protobuf; startup takes a few seconds. |

The app reads no configuration of its own — no environment variables, no
database, no volumes. Credentials for target agents are entered in the browser
and forwarded per request, so this chart creates no Secret.
