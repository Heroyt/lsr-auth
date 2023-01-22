<?php


namespace Lsr\Core\Auth\Middleware;


use Lsr\Core\App;
use Lsr\Core\Auth\Models\User;
use Lsr\Core\Auth\Services\Auth;
use Lsr\Core\Routing\Middleware;
use Lsr\Interfaces\RequestInterface;

class LoggedIn implements Middleware
{
	/**
	 * Middleware constructor.
	 *
	 * @param string[] $rights
	 */
	public function __construct(public readonly array $rights = []) {
	}

	/**
	 * Handles a request - checks if the user is logged in and has enough rights
	 *
	 * @param RequestInterface $request
	 *
	 * @return bool
	 */
	public function handle(RequestInterface $request) : bool {
		/** @var Auth $auth */
		$auth = App::getService('auth');
		if (!$auth->loggedIn()) {
			$request->addPassError('Pro přístup na tuto stránku se musíte přihlásit!');
			App::redirect('login', $request);
		}
		if (!empty($this->rights)) {
			/** @var User $user */
			$user = $auth->getLoggedIn();
			$allow = true;
			foreach ($this->rights as $right) {
				if (!$user->hasRight($right)) {
					$allow = false;
					break;
				}
			}
			if (!$allow) {
				$request->addPassError(lang('You don\'t have permission to access this page.', context: 'errors'));
				App::redirect([], $request);
			}
		}
		return true;
	}

}
