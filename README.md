# LSR Auth

`lsr/auth` supplies session-based authentication, ORM-backed users and user types, rights checks and route middleware for the Laser framework. Its namespace is `Lsr\Core\Auth`.

## Requirements

- PHP `>=8.4`.
- LSR interfaces `^0.3.4`, ORM `^0.3.7` and routing `^0.3.1 || ^0.4`.
- Nette DI and Nette Security `^3.2`.
- No PHP extensions are declared directly; ORM/database dependencies impose their own platform requirements. See [composer.json](composer.json).
- A configured LSR database/ORM environment, application session implementation and user/rights schema. The supplied migrations use MySQL-style InnoDB definitions.
- Framework serialization/wakeup integration uses `Lsr\Core\App` from `lsr/core`, which is not a direct requirement in this package's manifest. Supply core if using that integration.

## Installation

```sh
composer require lsr/auth
```

## Application integration

This package is not a complete login UI or a standalone identity server. Configure the application's persistence and session infrastructure before using the auth service:

1. Adapt and apply [migrations.neon](migrations.neon) through the application's migration workflow. It defines users, user types, rights and the user/user-type rights relations; Composer installation does not create these tables.
2. Provide an initialized `Lsr\Interfaces\SessionInterface` implementation and `Nette\Security\Passwords`.
3. Include [services.neon](services.neon) in the application's Nette DI configuration, or construct [`Lsr\Core\Auth\Services\Auth`](src/Services/Auth.php) with those services. The supplied configuration calls `init()` and exposes `parameters.auth.userClass` for a custom subclass of [`User`](src/Models/User.php). Preserve the column contract used by authentication, including `id_user`, `email` and `password`.
4. Initialize auth state for the current request before checking it. `init()` restores the user from the session's `usr` entry and reloads its database state. Session storage must be application-controlled: this value is serialized PHP user data, not a client-provided token.

The service API includes:

- `login($email, $password, $remember = false): bool`: checks the password with Nette Security, rehashes it when needed and stores the authenticated user in the session. Invalid credentials return `false`. The remember option changes session lifetime; it is not a separate remember-me token system.
- `register($email, $password, $name = ''): ?User`: hashes the password and inserts a user, returning the user or `null`; duplicate email raises `DuplicateEmailException`. Registration uses the host user type when available, so configure user types as part of application provisioning.
- `loggedIn()`, `getLoggedIn()`, `hasRight()` and `getRights()`: inspect authentication and rights.
- `logout()`: removes the session user and clears the service's current user.

See [`User`](src/Models/User.php) and [`UserType`](src/Models/UserType.php) for individual and inherited rights behavior. Application-specific registration validation, CSRF handling, rate limiting and HTTP endpoints remain application responsibilities.

## Route middleware

[`Lsr\Core\Auth\Middleware\LoggedIn`](src/Middleware/LoggedIn.php) refreshes auth state and requires a logged-in user. Its `rights` array combines top-level entries with AND and nested arrays with OR. For example, `['users.read', ['users.edit', 'admin']]` requires `users.read` and at least one of the other two rights.

[`LoggedOut`](src/Middleware/LoggedOut.php) restricts a route to unauthenticated users. Both middleware classes use `DispatchBreakException` redirects rather than returning JSON authentication errors. Configure the exception response factory and an application dispatcher that handles these exceptions. `LoggedIn` expects an `Lsr\Core\Requests\Request`; optional session injection enables flash messages.

## Development

CI runs on PHP 8.4 and 8.5. Install development dependencies and run the same three checks locally:

```sh
composer install --prefer-dist --no-interaction --no-progress
composer cs
vendor/bin/phpstan analyse --no-progress
vendor/bin/phpunit --no-coverage
```

[`phpunit.xml`](phpunit.xml) loads the lifecycle, middleware and user-type rights regression tests. Lifecycle and middleware tests use test doubles; rights tests use an in-memory SQLite database through `pdo_sqlite`. No external services are needed. The development dependency on `lsr/core` supplies framework types for [`phpstan.neon`](phpstan.neon), without requiring a sibling checkout.

Run `composer cs` to check PHP coding style and `composer cs:fix` (or `composer cbf`) to apply fixes with PHP CS Fixer. The rules and source paths are defined in [.php-cs-fixer.php](.php-cs-fixer.php).

## AI coding assistance

See [LSR Skills](https://github.com/Heroyt/lsr-skills) for AI agent skills for working with the LSR framework.

## License

Licensed under the [MIT License](LICENSE).
