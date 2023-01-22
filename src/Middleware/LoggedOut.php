<?php


namespace Lsr\Core\Auth\Middleware;


use Lsr\Core\App;
use Lsr\Core\Auth\Services\Auth;
use Lsr\Core\Routing\Middleware;
use Lsr\Interfaces\RequestInterface;

class LoggedOut implements Middleware
{

	public function __construct(
		protected readonly string $redirect = 'admin'
	) {
	}

	/**
	 * Handles a request - checks if the user is logged out
	 *
	 * @param RequestInterface $request
	 *
	 * @return bool
	 */
	public function handle(RequestInterface $request) : bool {
		/** @var Auth $auth */
		$auth = App::getService('auth');
		bdump($auth, 'LoggedOutMiddleware');
		if ($auth->loggedIn()) {
			App::redirect($this->redirect, $request);
		}
		return true;
	}

}
