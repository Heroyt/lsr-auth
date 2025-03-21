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
     * @param  list<non-empty-string|non-empty-string[]>  $rights  List of rights. The first level is AND, the second
     *     level (nested list) is OR.
     * @param  non-empty-string|array<int|string, string>  $unauthorizedUri
     * @param  non-empty-string|array<int|string, string>  $forbiddenUri
     */
    public function __construct(
        protected Auth $auth,
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
        assert($request instanceof Request);
        $this->auth->init();
        if (!$this->auth->loggedIn()) {
            $this->unauthorized($request);
        }
        if (!empty($this->rights)) {
            /** @var User $user */
            $user = $this->auth->getLoggedIn();
            // First level is AND, second level is OR
            foreach ($this->rights as $right) {
                if (is_string($right)) {
                    if (!$user->hasRight($right)) {
                        $this->forbid($request);
                    }
                }
                else if (is_array($right)) {
                    $hasRight = false;
                    foreach ($right as $subRight) {
                        if ($user->hasRight($subRight)) {
                            $hasRight = true;
                            break;
                        }
                    }
                    if (!$hasRight) {
                        $this->forbid($request);
                    }
                }
            }
        }

        return $handler->handle($request);
    }

    protected function unauthorized(Request $request) : never {
        $request->addPassError($this->unauthorizedMessage);
        throw new RedirectException(
        // @phpstan-ignore argument.type
                     $this->unauthorizedUri instanceof UriInterface ?
                         (string) $this->unauthorizedUri : $this->unauthorizedUri,
            request: $request,
        );
    }

    protected function forbid(Request $request) : never {
        $request->addPassError($this->forbiddenMessage);
        throw new RedirectException(
        // @phpstan-ignore argument.type
                     $this->forbiddenUri instanceof UriInterface ?
                         (string) $this->forbiddenUri : $this->forbiddenUri,
            request: $request,
        );
    }

}
