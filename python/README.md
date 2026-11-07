# harar

harar's client for Python.

```python
from harar import vault

v = vault(socket="/run/harar.sock")
v.hosts("prod/shop/STRIPE_KEY")                   # where it may go: ['api.stripe.com']
v.send("prod/shop/STRIPE_KEY", "api.stripe.com")  # the key, for that host only
```

harar decides every send and records the host, and this client holds
nothing. It speaks to a per-user agent (`harar agent`, where `harar hosts
allow <secret> <host>` sets the hosts) or a primary (where a role's `send`
permission does). A refusal, or a harar that cannot be reached, raises
`harar.HararError` naming why.

harar itself: https://github.com/addiscorp/harar
