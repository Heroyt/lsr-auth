<?php


namespace Lsr\Core\Auth\Middleware;


use Lsr\Core\Auth\Models\User;
use Lsr\Core\Auth\Services\Auth;
use Lsr\Core\Requests\Request;
use Lsr\Core\Routing\Middleware;
use Lsr\Exceptions\RedirectException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

readonly class LoggedIn implements Middleware
{
    /**
     * Middleware constructor.
     *
     * @template T of User
     * @param  Auth<T>  $auth
     * @param  string[]  $rights
     */
    public function __construct(
        private Auth  $auth,
        public array  $rights = [],
        public string $unauthorizedMessage = 'Pro přístup na tuto stránku se musíte přihlásit!',
        public string $forbiddenMessage = 'Na tuto stránku nemáte přístup',
    ) {}

    /**
     * Handles a request - checks if the user is logged in and has enough rights
     *
     * @param  ServerRequestInterface  $request
     * @param  RequestHandlerInterface  $handler
     *
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler) : ResponseInterface {
        if (!$this->auth->loggedIn()) {
            assert($request instanceof Request);
            $request->addPassError($this->unauthorizedMessage);
            throw new RedirectException('login', request: $request);
        }
        if (!empty($this->rights)) {
            /** @var User $user */
            $user = $this->auth->getLoggedIn();
            foreach ($this->rights as $right) {
                if (!$user->hasRight($right)) {
                    assert($request instanceof Request);
                    $request->addPassError($this->forbiddenMessage);
                    throw new RedirectException(request: $request);
                }
            }
        }

        return $handler->handle($request);
    }

}
