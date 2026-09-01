<?php

declare(strict_types=1);

namespace Lsr\Core\Auth\Lifecycle;

interface AuthLifecycleHookInterface
{
    public function record(AuthLifecycleEvent $event): void;
}
