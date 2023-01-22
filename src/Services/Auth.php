<?php

namespace Lsr\Core\Auth\Services;

use Lsr\Core\Auth\Exceptions\DuplicateEmailException;
use Lsr\Core\Auth\Models\User;
use Lsr\Core\Auth\Models\UserType;
use Lsr\Core\DB;
use Lsr\Core\Exceptions\ModelNotFoundException;
use Lsr\Core\Exceptions\ValidationException;
use Lsr\Interfaces\SessionInterface;
use Lsr\Logging\Exceptions\DirectoryCreationException;
use Nette\Security\Passwords;

class Auth
{

	protected ?User $loggedIn = null;

	/**
	 * @param SessionInterface   $session
	 * @param Passwords          $passwords
	 * @param class-string<User> $userClass
	 */
	public function __construct(
		private readonly SessionInterface $session,
		private readonly Passwords        $passwords,
		private readonly string           $userClass = User::class,
	) {
	}

	public static function logout() : void {
		unset($_SESSION['usr']);
		self::$loggedIn = null;
	}

	/**
	 * Check if the user is logged in and populate the static variable
	 *
	 * @return void
	 * @throws ModelNotFoundException
	 * @throws ValidationException
	 * @throws DirectoryCreationException
	 */
	public function init() : void {
		/** @var string|null $usr */
		$usr = $this->session->get('usr');
		if (isset($usr)) {
			/** @var User|false $user */
			$user = unserialize($usr, [User::class]);
			if ($user !== false) {
				$user->fetch(true);
				$this->loggedIn = $user;
			}
		}
	}

	/**
	 * Try to log in a user
	 *
	 * @param string $email
	 * @param string $password
	 *
	 * @return bool If the login was successful
	 * @throws DirectoryCreationException
	 * @throws ModelNotFoundException
	 * @throws ValidationException
	 */
	public function login(string $email, string $password) : bool {
		$user = DB::select(($this->userClass)::TABLE, '*')->where('[email] = %s', $email)->fetch();
		if (!isset($user)) {
			return false; // User does not exist
		}
		if (!$this->passwords->verify($password, $user->password)) {
			return false; // Invalid password
		}
		$this->loggedIn = ($this->userClass)::get((int) $user->{($this->userClass)::getPrimaryKey()}, $user);

		if ($this->passwords->needsRehash($user->password)) {
			$this->loggedIn->password = $this->passwords->hash($password);
			$this->loggedIn->save();
		}
		$this->session->set('usr', serialize($this->loggedIn));
		return true;
	}

	/**
	 * Register a new user
	 *
	 * @param string $email
	 * @param string $password
	 * @param string $name
	 *
	 * @return User|null
	 * @throws DuplicateEmailException
	 */
	public function register(string $email, string $password, string $name = '') : ?User {
		$check = DB::select(($this->userClass)::TABLE, 'COUNT(*)')->where('[email] = %s', $email)->fetchSingle();
		if ($check > 0) {
			throw new DuplicateEmailException('User with this email already exists');
		}

		$user = new ($this->userClass);
		$user->name = $name;
		$user->email = $email;
		$user->password = $this->passwords->hash($password);
		$user->type = UserType::getHostUserType();
		$user->id_user_type = isset($user->type) ? $user->type->id : 1;
		try {
			if ($user->insert()) {
				return $user;
			}
		} catch (ValidationException $e) {
			// TODO: Handle validation error
		}

		return null;
	}

	public function loggedIn() : bool {
		return isset($this->loggedIn);
	}

	/**
	 * @return User|null
	 */
	public function getLoggedIn() : ?User {
		return $this->loggedIn;
	}
}