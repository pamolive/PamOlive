# Licensing and editions

PamOlive separates the open-source product from paid cluster usage with edition
guardrails and signed commercial licenses.

## Editions

| Edition | Cluster | Users | Targets | Intended usage |
| --- | --- | --- | --- | --- |
| Community | No | Unlimited | Unlimited | Single-node production |
| Lab | Yes | 5 active users max | 2 targets max | Cluster evaluation only |
| Business | Licensed | License-defined | License-defined | Production |
| Enterprise | Licensed | License-defined | License-defined | Production HA |

Community and Lab are built-in. Business and Enterprise require a signed license.

## Runtime variables

```env
PAMOLIVE_EDITION=community
PAMOLIVE_CLUSTER_ENABLED=false
PAMOLIVE_NODE_ID=node-1
PAMOLIVE_LICENSE_FILE=/run/secrets/pamolive_license.json
PAMOLIVE_LICENSE_PUBLIC_KEY_FILE=/run/secrets/pamolive_license_public.pem
```

`PAMOLIVE_NODE_ID` must be stable per VM, for example `vm-1` and `vm-2`.

## Generate Mopacy signing keys

Generate the private/public key pair outside the public repository:

```bash
openssl genpkey -algorithm Ed25519 -out pamolive-license-private.pem
openssl pkey -in pamolive-license-private.pem -pubout -out pamolive-license-public.pem
```

Keep `pamolive-license-private.pem` offline and private to Mopacy. Only the public
key is deployed to PamOlive installations.

## Generate a commercial license

```bash
python tools/generate_license.py \
  --private-key pamolive-license-private.pem \
  --customer "Client Example" \
  --edition business \
  --feature cluster \
  --max-users 50 \
  --max-targets 100 \
  --max-nodes 2 \
  --domain pamolive.client.example \
  --expires-at 2027-07-28T00:00:00Z \
  --output pamolive-license.json
```

Mount the license and public key as Docker secrets or read-only files.

## Open-source boundary

Open-source code can always be forked and modified. PamOlive therefore relies on
signed official builds, commercial support, private enterprise modules, trademark
control, and signed licenses rather than pretending client-side code is impossible
to change.

