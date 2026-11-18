# Your own image from your laptop

You built an image on your laptop and it runs there. Nodes cannot see your
laptop's images: every node pulls the image from a registry. This guide
builds the image for the nodes' architecture, pushes it to a registry,
and deploys it.

**You will use:** [`armada app create`](../cli/armada-app.md#armada-app-create),
[`armada secret set`](../cli/armada-secret.md#armada-secret-set),
[`registry`](../spec-reference.md#registry)

**Before you start:** a running cluster ([quickstart](../quickstart.md)),
an image that runs on your laptop, and an account at a registry. This
guide uses `ghcr.io` (GitHub's registry) with the user `acme`; any
registry that speaks the OCI distribution API works the same way.

## The setup

```
  laptop: build (amd64 + arm64) --push--> ghcr.io/acme/hello:1.0.0
                                                 |
                       every node pulls it  <----+   (with credentials if private)
```

## 1. Know the nodes' architecture

```bash
armada node list
```

The `armada.arch` label of each node says `amd64` or `arm64`. Most cloud
machines and servers are `amd64`; a Mac with Apple silicon builds `arm64`
images by default, which an `amd64` node cannot run.

## 2. Build for the nodes and push

Build one image with a variant for each architecture, and push it with a
version tag. With `docker buildx`, for example:

```bash
docker login ghcr.io -u acme                # a token with write:packages
docker buildx build --platform linux/amd64,linux/arm64 \
  -t ghcr.io/acme/hello:1.0.0 --push .
```

Other build tools take the same two things: the platforms (`linux/amd64`,
`linux/arm64`) and a registry reference to push to. Use a version tag
rather than `latest`: Armada pins the digest the tag points to when it
deploys, and a tag per version keeps rollbacks and history readable.

## 3. Deploy it

**A public image** needs nothing more:

```bash
armada app create hello --image ghcr.io/acme/hello:1.0.0 --port 8080 --ingress external
armada app show hello
```

On `ghcr.io`, a new package is private; make it public in the package's
settings on GitHub, or use the credentials below.

**A private image** needs a read-only token as a secret of the app, and the
registry user:

```bash
printf '%s' "$GHCR_READ_TOKEN" | armada secret set hello ghcr-token
armada app create hello --image ghcr.io/acme/hello:1.0.0 --port 8080 --ingress external \
  --registry-user acme --registry-secret ghcr-token
```

[A private registry](private-registry.md) explains where those credentials
go.

## 4. Ship a new version

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/acme/hello:1.0.1 --push .
armada app update hello --image ghcr.io/acme/hello:1.0.1 --wait
```

## Check that it works

```bash
armada app show hello      # READY 1/1, the image and its digest
armada app events hello    # Scheduled, Started, Ready, or why not
```

To open the app from your laptop without a domain, see
[Apps on a private network without a domain](private-network.md).

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `pull …: the image does not exist, or it is private and the app has no registry credentials` | A typo in the name (registries answer a name that does not exist like a private one), the image was never pushed, or it is private | Compare the name with the registry's page letter by letter; push it; or add `--registry-user` and `--registry-secret` |
| The same message with credentials given | The token cannot read the package, or the user does not match | Give the token read access to the package (`read:packages` on `ghcr.io`); `armada secret set` it again |
| `no ready node can run the image, which is built for linux/arm64` | The image has no variant for the nodes' architecture | Build with `--platform linux/amd64,linux/arm64` (step 2) and deploy the new tag |
| The app runs an older build after a push to the same tag | The revision pinned the digest the tag pointed to when it was deployed | Push a new tag and `armada app update --image` it |
