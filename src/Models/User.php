<?php

namespace Lsr\Core\Auth\Models;

use Lsr\ObjectValidation\Attributes\Email;
use Lsr\Orm\Attributes\PrimaryKey;
use Lsr\Orm\Attributes\Relations\ManyToOne;
use Lsr\Orm\Model;

#[PrimaryKey('id_user')]
class User extends Model
{

    public const string TABLE = 'users';

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
}