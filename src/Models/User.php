<?php

namespace Lsr\Core\Auth\Models;

use Lsr\Core\App;
use Lsr\Core\Auth\Services\Auth;
use Lsr\Core\Models\Attributes\ManyToOne;
use Lsr\Core\Models\Attributes\PrimaryKey;
use Lsr\Core\Models\Attributes\Validation\Email;
use Lsr\Core\Models\Model;
use Nette\Security\Passwords;

#[PrimaryKey('id_user')]
class User extends Model
{

	public const TABLE = 'users';

	public string   $name;
	#[ManyToOne]
	public UserType $type;
	#[Email]
	public string   $email;
	/** @var string Password hash */
	public string $password;


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
		/** @var Passwords $passwords */
		$passwords = App::getService('passwords');
		$this->password = $passwords->hash($password);
		return $this;
	}

	public function delete() : bool {
		/** @var Auth $auth */
		$auth = App::getService('auth');
		if ($auth->loggedIn() && $this->id === $auth->getLoggedIn()?->id) {
			return false; // Cannot delete current user
		}
		return parent::delete();
	}
}