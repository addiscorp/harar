# addis/harar

harar's client for PHP (8.1 and newer).

```sh
composer require addis/harar
```

```php
// The harar agent on this machine (`harar agent`): no account, no token.
$harar = Harar\vault();

// A harar:// reference names a vault key, as op:// names a 1Password field.
$key = $harar->secrets->resolve('harar://prod/shop/STRIPE_KEY');
[$a, $b] = $harar->secrets->resolveAll(['harar://prod/shop/STRIPE_KEY', 'harar://prod/site/DATABASE_URL']);
```

The value is read when you ask for it and held only by your program; nothing
is written to disk. The agent answers only the user it runs as, and the first
time a terminal asks, it asks you to approve (Touch ID on a Mac).
`Harar\vault(socket: '/run/harar.sock')` talks to a primary instead.

A gateway that attaches keys on their way out (`import { gateway } from
'rixse'`) asks where each may go, and for it for one host only:
`hosts(secret)` and `send(secret, host)`. A refusal, or a harar that cannot be reached, throws `Harar\HararError` naming why.

The package is the root `composer.json` of this repository; Packagist takes
each stable `vX.Y.Z` tag as a version.

harar itself: https://github.com/addiscorp/harar
