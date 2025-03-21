<?php


namespace Lsr\Core\Auth\Middleware;


use Lsr\Core\Auth\Models\User;
use Lsr\Core\Auth\Services\Auth;
use Lsr\Core\Routing\Middleware;
use Lsr\Exceptions\RedirectException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

readonly class LoggedOut implements Middleware
{

    /**
     * @template T of User
     * @param  Auth<T>  $auth
     * @param  non-empty-string|array<string|int,string>  $redirect
     */
    public function __construct(
        private Auth             $auth,
        protected string | array $redirect = 'admin',
    ) {}

    /**
     * Handles a request - checks if the user is logged out
     *
     * @param  ServerRequestInterface  $request
     * @param  RequestHandlerInterface  $handler
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler) : ResponseInterface {
        $this->auth->init();
        if ($this->auth->loggedIn() && $this->auth->getLoggedIn() !== null) {
            throw new RedirectException($this->redirect);
        }
        return $handler->handle($request);
    }

}
