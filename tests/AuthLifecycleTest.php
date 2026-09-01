<?php

declare(strict_types=1);

namespace TestCases;

use Lsr\Core\Auth\Lifecycle\AuthLifecycleEvent;
use Lsr\Core\Auth\Services\Auth;
use Lsr\Interfaces\SessionInterface;
use Nette\Security\Passwords;
use PHPUnit\Framework\TestCase;

final class AuthLifecycleTest extends TestCase
{
    public function testLogoutReportsOutcomeWithoutUserOrSessionData(): void
    {
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

    public function testHookFailureDoesNotAffectLogout(): void
    {
        $session = $this->createMock(SessionInterface::class);
        $session->expects(self::once())->method('delete')->with('usr');
        $hook = new RecordingAuthLifecycleHook();
        $hook->fail = true;
        $auth = (new Auth($session, new Passwords()))->setLifecycleHook($hook);

        $auth->logout();
    }

    public function testLifecycleHookIsExcludedFromSerialization(): void
    {
        $auth = (new \ReflectionClass(Auth::class))->newInstanceWithoutConstructor();
        $auth->setLifecycleHook(new RecordingAuthLifecycleHook());

        self::assertStringNotContainsString(RecordingAuthLifecycleHook::class, serialize($auth));
    }
}
