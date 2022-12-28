<?php

namespace Lsr\Core\Auth\Models;

use Lsr\Core\DB;
use Lsr\Core\Exceptions\ModelNotFoundException;
use Lsr\Core\Exceptions\ValidationException;
use Lsr\Core\Models\Attributes\ManyToOne;
use Lsr\Core\Models\Attributes\PrimaryKey;
use Lsr\Core\Models\Attributes\Validation\Email;
use Lsr\Core\Models\Model;
use Lsr\Logging\Exceptions\DirectoryCreationException;
use Nette\Security\Passwords;

#[PrimaryKey('id_user')]
class User extends Model
{

	public const TABLE = 'users';

	protected static ?User $loggedIn = null;

	public string   $name;
	#[ManyToOne]
	public UserType $type;
	#[Email]
	public string   $email;
	/** @var string Password hash */
	public string $password;

	/**
	 * Check if the user is logged in and populate the static variable
	 *
	 * @return void
	 * @throws ModelNotFoundException
	 * @throws ValidationException
	 * @throws DirectoryCreationException
	 */
	public static function init() : void {
		if (isset($_SESSION['usr'])) {
			/** @var static|false $user */
			$user = unserialize($_SESSION['usr'], [static::class]);
			if ($user !== false) {
				$user->fetch(true);
				self::$loggedIn = $user;
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
	public static function login(string $email, string $password) : bool {
		$passwords = new Passwords();
		$user = DB::select(self::TABLE, '*')->where('[email] = %s', $email)->fetch();
		if (!isset($user)) {
			return false; // User does not exist
		}
		if (!$passwords->verify($password, $user->password)) {
			return false; // Invalid password
		}
		self::$loggedIn = static::get((int) $user->{static::getPrimaryKey()}, $user);
		if ($passwords->needsRehash($user->password)) {
			self::$loggedIn->password = $passwords->hash($password);
			self::$loggedIn->save();
		}
		$_SESSION['usr'] = serialize(self::$loggedIn);
		return true;
	}

	public static function logout() : void {
		unset($_SESSION['usr']);
		self::$loggedIn = null;
	}

	public static function register(string $email, string $password, string $name = '') : ?User {
		// TODO: Check duplicate emails

		$passwords = new Passwords();
		$user = new static();
		$user->name = $name;
		$user->email = $email;
		$user->password = $passwords->hash($password);
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

	/**
	 * @return string[]
	 */
	public function getRights() : array {
		return $this->type->getRights();
	}

	public function hasRight(string $right) : bool {
		return $this->type->hasRight($right);
	}

	/**
	 * Sets (and hashes) a new user's password
	 *
	 * @param string $password
	 *
	 * @return User
	 */
	public function setPassword(string $password) : User {
		$passwords = new Passwords();
		$this->password = $passwords->hash($password);
		return $this;
	}

	public function delete() : bool {
		if (static::loggedIn() && $this->id === static::getLoggedIn()?->id) {
			return false; // Cannot delete current user
		}
		return parent::delete();
	}

	public static function loggedIn() : bool {
		return isset(self::$loggedIn);
	}

	/**
	 * @return User|null
	 */
	public static function getLoggedIn() : ?User {
		return self::$loggedIn;
	}
}