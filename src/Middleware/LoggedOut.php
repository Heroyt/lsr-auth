<?php


namespace Lsr\Core\Auth\Middleware;


use Lsr\Core\Routing\Middleware;
use Lsr\Interfaces\RequestInterface;

class LoggedOut implements Middleware
{

	/**
	 * Handles a request - checks if the user is logged out
	 *
	 * @param RequestInterface $request
	 *
	 * @return bool
	 */
	public function handle(RequestInterface $request) : bool {
		if (User::loggedIn()) {
			App::redirect('admin', $request);
			return false;
		}
		return true;
	}

}
