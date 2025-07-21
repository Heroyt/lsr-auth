<?php


namespace Lsr\Core\Auth\Middleware;


use Lsr\Core\Auth\Models\User;
use Lsr\Core\Auth\Services\Auth;
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
readonly class LoggedOut implements Middleware
{

    /**
     * @param  Auth<T>  $auth
     */
    public function __construct(
        protected Auth                  $auth,
        public string                   $message = 'Již jste přihlášen.',
        protected string | UriInterface $redirect = '/',
        protected ?SessionInterface     $session = null,
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
            $this->session?->flashWarning($this->message);
            $this->session?->flash('fromRequest', serialize($request));
            throw DispatchBreakException::createRedirect($this->redirect);
        }
        return $handler->handle($request);
    }

}
