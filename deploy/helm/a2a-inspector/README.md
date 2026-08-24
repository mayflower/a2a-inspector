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
| `imagePullSecrets` | `[]` | The GHCR package is public; set this only for a registry that needs authentication. |
| `service.port` / `service.targetPort` | `80` / `8080` | The container listens on 8080. |
| `ingress.host` | `a2a-inspector.data.mayflower.zone` | |
| `securityContext.readOnlyRootFilesystem` | `true` | Works because the chart mounts an `emptyDir` at `/tmp` and the image sets `HOME=/tmp`. |
| `startupProbe.failureThreshold` | `30` | Importing `a2a-sdk[all]` pulls grpc and protobuf; startup takes a few seconds. |

The app has no database and no volumes. Credentials for target agents are
entered in the browser and forwarded per request, so this chart creates no
Secret.

## OAuth 2.0

Nothing has to be configured. The OAuth redirect URI needs the public
hostname, which cannot be derived from the request behind an ingress, so the
chart sets `OAUTH_REDIRECT_BASE_URL` from `ingress.host` for you. Override it
only if the inspector is reached under a name other than its ingress:

```yaml
oauth:
  redirectBaseUrl: https://inspector.example.internal
```

With no ingress the variable is omitted and the app falls back to
`X-Forwarded-Proto` and `X-Forwarded-Host`.

The one thing that cannot be automated is the identity provider's side: the
redirect URI has to be allowed there. Register `https://<host>/oauth/callback`
— unless the provider supports dynamic client registration (RFC 7591), in
which case the inspector registers itself on first login and there is nothing
to do at all.

The inspector authenticates as a public client using PKCE, so no client
secret has to be stored anywhere.
