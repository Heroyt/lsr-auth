<?php


namespace Lsr\Core\Auth\Middleware;


use Lsr\Core\App;
use Lsr\Core\Auth\Services\Auth;
use Lsr\Core\Routing\Middleware;
use Lsr\Interfaces\RequestInterface;

class LoggedOut implements Middleware
{

	protected readonly Auth $auth;

	public function __construct(
		protected readonly string $redirect = 'admin'
	) {
		/**
		 * @noinspection PhpFieldAssignmentTypeMismatchInspection
		 * @phpstan-ignore-next-line
		 */
		$this->auth = App::getService('auth');
	}

	/**
	 * Handles a request - checks if the user is logged out
	 *
	 * @param RequestInterface $request
	 *
	 * @return bool
	 */
	public function handle(RequestInterface $request) : bool {
		if ($this->auth->loggedIn()) {
			App::redirect($this->redirect, $request);
		}
		return true;
	}

}
