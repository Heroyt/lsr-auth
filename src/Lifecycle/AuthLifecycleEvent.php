<?php

declare(strict_types=1);

namespace Lsr\Core\Auth\Lifecycle;

final readonly class AuthLifecycleEvent
{
    public const string LOGIN = 'login';
    public const string REGISTER = 'register';
    public const string LOGOUT = 'logout';

    public const string SUCCESS = 'success';
    public const string INVALID_CREDENTIALS = 'invalid_credentials';
    public const string DUPLICATE = 'duplicate';
    public const string INVALID = 'invalid';
    public const string FAILED = 'failed';
    public const string ERROR = 'error';

    public function __construct(
        public string $operation,
        public string $outcome,
        public float $durationSeconds,
        public ?string $errorType = null,
    ) {
    }
}
