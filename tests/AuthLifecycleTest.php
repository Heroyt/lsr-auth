<?php

declare(strict_types=1);

namespace TestCases;

use Lsr\Core\Auth\Lifecycle\AuthLifecycleEvent;
use Lsr\Core\Auth\Services\Auth;
use Lsr\Interfaces\SessionInterface;
use Nette\Security\Passwords;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class AuthLifecycleTest extends TestCase
{
    public function test_logout_reports_outcome_without_user_or_session_data(): void {
        $session = $this->createMock(SessionInterface::class);
        $session->expects(self::once())->method('delete')->with('usr');
        $hook = new RecordingAuthLifecycleHook();
        $auth = (new Auth($session, new Passwords()))->setLifecycleHook($hook);

        $auth->logout();

        self::assertCount(1, $hook->events);
        self::assertSame(AuthLifecycleEvent::LOGOUT, $hook->events[0]->operation);
        self::assertSame(AuthLifecycleEvent::SUCCESS, $hook->events[0]->outcome);
        self::assertNull($hook->events[0]->errorType);
        self::assertGreaterThanOrEqual(0.0, $hook->events[0]->durationSeconds);
    }

    public function test_hook_failure_does_not_affect_logout(): void {
        $session = $this->createMock(SessionInterface::class);
        $session->expects(self::once())->method('delete')->with('usr');
        $hook = new RecordingAuthLifecycleHook();
        $hook->fail = true;
        $auth = (new Auth($session, new Passwords()))->setLifecycleHook($hook);

        $auth->logout();
    }

    public function test_lifecycle_hook_is_excluded_from_serialization(): void {
        $auth = (new ReflectionClass(Auth::class))->newInstanceWithoutConstructor();
        $auth->setLifecycleHook(new RecordingAuthLifecycleHook());

        self::assertStringNotContainsString(RecordingAuthLifecycleHook::class, serialize($auth));
    }
}
