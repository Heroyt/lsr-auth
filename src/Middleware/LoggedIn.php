<?php


namespace Lsr\Core\Auth\Middleware;


use Lsr\Core\Routing\Middleware;
use Lsr\Interfaces\RequestInterface;

class LoggedIn implements Middleware
{

	/**
	 * @var string[]
	 */
	public array $rights = [];

	/**
	 * Middleware constructor.
	 *
	 * @param string[] $rights
	 */
	public function __construct(array $rights = []) {
		$this->rights = $rights;
	}

	/**
	 * Handles a request - checks if the user is logged in and has enough rights
	 *
	 * @param RequestInterface $request
	 *
	 * @return bool
	 */
	public function handle(RequestInterface $request) : bool {
		if (!User::loggedIn()) {
			$request->passErrors[] = 'Pro přístup na tuto stránku se musíte přihlásit!';
			if (in_array('admin', $request->path, true)) {
				App::redirect('admin-login', $request);
			}
			else {
				App::redirect('login', $request);
			}
			return false;
		}
		if (!empty($this->rights)) {
			$allow = true;
			foreach ($this->rights as $right) {
				if (!User::hasRight($right)) {
					$allow = false;
					break;
				}
			}
			if (!$allow) {
				$request->passErrors[] = lang('You don\'t have permission to access this page.', context: 'errors');
				if (in_array('admin', $request->path, true)) {
					App::redirect('admin', $request);
				}
				else {
					App::redirect([], $request);
				}
			}
		}
		return true;
	}

}
