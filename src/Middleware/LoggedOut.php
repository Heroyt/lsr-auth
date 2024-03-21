<?php


namespace Lsr\Core\Auth\Middleware;


use Lsr\Core\App;
use Lsr\Core\Auth\Services\Auth;
use Lsr\Core\Routing\Middleware;
use Lsr\Interfaces\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

readonly class LoggedOut implements Middleware
{

	public function __construct(
		protected string $redirect = 'admin'
	) {
	}

	/**
	 * Handles a request - checks if the user is logged out
	 *
	 * @param RequestInterface $request
	 *
	 * @return bool
	 */
	public function process(ServerRequestInterface $request, RequestHandlerInterface $handler) : ResponseInterface {
		/** @var Auth $auth */
		$auth = App::getService('auth');
		bdump($auth, 'LoggedOutMiddleware');
		if ($auth->loggedIn()) {
			return App::redirect($this->redirect, $request);
		}
		return $handler->handle($request);
	}

}
