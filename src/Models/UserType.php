<?php

namespace Lsr\Core\Auth\Models;

use Lsr\Core\DB;
use Lsr\Core\Models\Attributes\PrimaryKey;
use Lsr\Core\Models\Model;

#[PrimaryKey('id_user_type')]
class UserType extends Model
{

	public const TABLE = 'user_types';

	public string $name = '';

	public bool $superAdmin = false;

	/** @var string[] */
	protected array $rights = [];
	/** @var array<string,bool> */
	protected array $hasRights = [];

	public static function getHostUserType() : ?UserType {
		return self::query()->where('[host] = 1')->first();
	}

	/**
	 * @return string[]
	 */
	public function getRights() : array {
		if (!isset($this->rights)) {
			$this->rights = DB::select('user_type_rights', 'right')
												->where('%n = %i', $this::getPrimaryKey(), $this->id)
												->fetchPairs();
		}
		return $this->rights;
	}

	public function hasRight(string $right) : bool {
		if ($this->superAdmin) {
			return true;
		}
		if (isset($this->hasRights[$right])) {
			return $this->hasRights[$right];
		}
		if (!empty($this->rights)) {
			$this->hasRights[$right] = in_array($right, $this->rights, true);
			return $this->hasRights[$right];
		}

		$test = DB::select('user_type_rights', 'COUNT(*)')
							->where('%n = %i AND [right] = %s', $this::getPrimaryKey(), $this->id, $right)
							->fetchSingle();
		$this->hasRights[$right] = $test > 0;
		return $this->hasRights[$right];
	}

}