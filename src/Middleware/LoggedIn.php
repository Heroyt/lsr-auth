<?php


namespace Lsr\Core\Auth\Middleware;


use Lsr\Core\Auth\Models\User;
use Lsr\Core\Auth\Services\Auth;
use Lsr\Core\Requests\Request;
use Lsr\Core\Routing\Middleware;
use Lsr\Exceptions\DispatchBreakException;
use Lsr\Interfaces\SessionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * @template T of User
 */
readonly class LoggedIn implements Middleware
{
    /**
     * Middleware constructor.
     *
     * @param  Auth<T>  $auth
     * @param  list<non-empty-string|non-empty-string[]>  $rights  List of rights. The first level is AND, the second
     *     level (nested list) is OR.
     */
    public function __construct(
        protected Auth               $auth,
        public array                 $rights = [],
        public string                $unauthorizedMessage = 'Pro přístup na tuto stránku se musíte přihlásit!',
        public string                $forbiddenMessage = 'Na tuto stránku nemáte přístup',
        public string | UriInterface $unauthorizedUri = 'login',
        public string | UriInterface $forbiddenUri = '/',
        protected ?SessionInterface  $session = null,
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
                    continue;
                }

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

        return $handler->handle($request);
    }

    protected function unauthorized(Request $request) : never {
        $this->session?->flashError($this->unauthorizedMessage);
        $this->session?->flash('fromRequest', serialize($request));
        throw DispatchBreakException::createRedirect($this->unauthorizedUri);
    }

    protected function forbid(Request $request) : never {
        $this->session?->flashError($this->forbiddenMessage);
        $this->session?->flash('fromRequest', serialize($request));
        throw DispatchBreakException::createRedirect($this->forbiddenUri);
    }

}
