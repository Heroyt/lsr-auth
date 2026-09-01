<?php

declare(strict_types=1);

namespace TestCases;

use Lsr\Core\Auth\Lifecycle\AuthLifecycleEvent;
use Lsr\Core\Auth\Lifecycle\AuthLifecycleHookInterface;
use RuntimeException;

final class RecordingAuthLifecycleHook implements AuthLifecycleHookInterface
{
    /** @var list<AuthLifecycleEvent> */
    public array $events = [];
    public bool $fail = false;

    public function record(AuthLifecycleEvent $event): void
    {
        if ($this->fail) {
            throw new RuntimeException('Hook failure');
        }
        $this->events[] = $event;
    }
}
