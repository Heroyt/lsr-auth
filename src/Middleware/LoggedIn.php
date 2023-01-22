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
	 * @var string[]
	 */
	public array $rights = [];

	protected readonly Auth $auth;

	/**
	 * Middleware constructor.
	 *
	 * @param string[] $rights
	 */
	public function __construct(array $rights = []) {
		$this->rights = $rights;
		/**
		 * @noinspection PhpFieldAssignmentTypeMismatchInspection
		 * @phpstan-ignore-next-line
		 */
		$this->auth = App::getService('auth');
	}

	/**
	 * Handles a request - checks if the user is logged in and has enough rights
	 *
	 * @param RequestInterface $request
	 *
	 * @return bool
	 */
	public function handle(RequestInterface $request) : bool {
		if (!$this->auth->loggedIn()) {
			$request->passErrors[] = 'Pro přístup na tuto stránku se musíte přihlásit!';
			App::redirect('login', $request);
		}
		if (!empty($this->rights)) {
			/** @var User $user */
			$user = $this->auth->getLoggedIn();
			$allow = true;
			foreach ($this->rights as $right) {
				if (!$user->hasRight($right)) {
					$allow = false;
					break;
				}
			}
			if (!$allow) {
				$request->passErrors[] = lang('You don\'t have permission to access this page.', context: 'errors');
				App::redirect([], $request);
			}
		}
		return true;
	}

}
