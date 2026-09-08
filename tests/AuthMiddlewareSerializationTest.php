<?php

declare(strict_types=1);

namespace TestCases;

use Lsr\Core\Auth\Middleware\LoggedIn;
use Lsr\Core\Auth\Middleware\LoggedOut;
use Lsr\Core\Auth\Models\User;
use Lsr\Core\Auth\Services\Auth;
use Lsr\Core\Requests\Request;
use Lsr\Exceptions\DispatchBreakException;
use Lsr\Interfaces\SessionInterface;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Server\RequestHandlerInterface;

final class AuthMiddlewareSerializationTest extends TestCase
{
    public function test_logged_out_redirect_ignores_runtime_request_attributes(): void {
        $user = $this->createStub(User::class);
        $auth = $this->createStub(Auth::class);
        $auth->method('loggedIn')->willReturn(true);
        $auth->method('getLoggedIn')->willReturn($user);
        $session = $this->createMock(SessionInterface::class);
        $session->expects(self::once())->method('flashWarning');
        $session->expects(self::never())->method('flash');
        $request = (new Request(new ServerRequest('GET', '/login')))
            ->withAttribute('runtimeService', static fn () => null);

        $this->expectException(DispatchBreakException::class);

        (new LoggedOut($auth, session: $session))->process(
            $request,
            $this->createStub(RequestHandlerInterface::class),
        );
    }

    public function test_logged_in_unauthorized_redirect_ignores_runtime_request_attributes(): void {
        $auth = $this->createStub(Auth::class);
        $auth->method('loggedIn')->willReturn(false);
        $session = $this->createMock(SessionInterface::class);
        $session->expects(self::once())->method('flashError');
        $session->expects(self::never())->method('flash');
        $request = (new Request(new ServerRequest('GET', '/account')))
            ->withAttribute('runtimeService', static fn () => null);

        $this->expectException(DispatchBreakException::class);

        (new LoggedIn($auth, session: $session))->process(
            $request,
            $this->createStub(RequestHandlerInterface::class),
        );
    }

    public function test_logged_in_forbidden_redirect_ignores_runtime_request_attributes(): void {
        $user = $this->createStub(User::class);
        $user->method('hasRight')->willReturn(false);
        $auth = $this->createStub(Auth::class);
        $auth->method('loggedIn')->willReturn(true);
        $auth->method('getLoggedIn')->willReturn($user);
        $session = $this->createMock(SessionInterface::class);
        $session->expects(self::once())->method('flashError');
        $session->expects(self::never())->method('flash');
        $request = (new Request(new ServerRequest('GET', '/administration')))
            ->withAttribute('runtimeService', static fn () => null);

        $this->expectException(DispatchBreakException::class);

        (new LoggedIn($auth, rights: ['administration'], session: $session))->process(
            $request,
            $this->createStub(RequestHandlerInterface::class),
        );
    }
}
