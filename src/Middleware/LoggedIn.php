<?php


namespace Lsr\Core\Auth\Middleware;


use Lsr\Core\Auth\Models\User;
use Lsr\Core\Auth\Services\Auth;
use Lsr\Core\Requests\Request;
use Lsr\Core\Routing\Middleware;
use Lsr\Exceptions\RedirectException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\RequestHandlerInterface;

readonly class LoggedIn implements Middleware
{
    /**
     * Middleware constructor.
     *
     * @template T of User
     * @param  Auth<T>  $auth
     * @param  non-empty-string[]  $rights
     * @param  non-empty-string|array<int|string, string>  $unauthorizedUri
     * @param  non-empty-string|array<int|string, string>  $forbiddenUri
     */
    public function __construct(
        private Auth                         $auth,
        public array                         $rights = [],
        public string                        $unauthorizedMessage = 'Pro přístup na tuto stránku se musíte přihlásit!',
        public string                        $forbiddenMessage = 'Na tuto stránku nemáte přístup',
        public array | string | UriInterface $unauthorizedUri = 'login',
        public array | string | UriInterface $forbiddenUri = [],
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
            throw new RedirectException(
                         $this->unauthorizedUri instanceof UriInterface ?
                             (string) $this->unauthorizedUri : $this->unauthorizedUri,
                request: $request,
            );
        }
        if (!empty($this->rights)) {
            /** @var User $user */
            $user = $this->auth->getLoggedIn();
            foreach ($this->rights as $right) {
                if (!$user->hasRight($right)) {
                    assert($request instanceof Request);
                    $request->addPassError($this->forbiddenMessage);
                    throw new RedirectException(
                                 $this->forbiddenUri instanceof UriInterface ?
                                     (string) $this->forbiddenUri : $this->forbiddenUri,
                        request: $request,
                    );
                }
            }
        }

        return $handler->handle($request);
    }

}
