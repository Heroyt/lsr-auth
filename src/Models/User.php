<?php

namespace Lsr\Core\Auth\Models;

use Lsr\Core\Models\Attributes\NoDB;
use Lsr\Db\DB;
use Lsr\ObjectValidation\Attributes\Email;
use Lsr\Orm\Attributes\PrimaryKey;
use Lsr\Orm\Attributes\Relations\ManyToOne;
use Lsr\Orm\Model;

#[PrimaryKey('id_user')]
class User extends Model
{

    public const string TABLE = 'users';
    public const string USER_RIGHTS_TABLE = 'user_rights';

	public string   $name;
	#[ManyToOne]
	public UserType $type;
	#[Email]
	public string   $email;
	/** @var string Password hash */
	public string $password;

    /** @var non-empty-string[] */
    #[NoDB]
    public array $rights {
        get {
            if (!isset($this->rights)) {
                /** @var non-empty-string[] $rights */
                $rights = DB::select($this::USER_RIGHTS_TABLE, 'right')
                            ->where('%n = %i', $this::getPrimaryKey(), $this->id)
                            ->fetchPairs();
                $this->rights = array_unique(array_merge($this->type->getRights(), $rights));
            }
            return $this->rights;
        }
    }

    /** @var array<non-empty-string, bool> */
    protected array $hasRights = [];

    /**
     * @return array{id: int}
     */
    public function __serialize() : array {
        return [
            'id'    => $this->id,
            'email' => $this->email,
        ];
    }

    /**
     * @param  array{id: int}  $data
     */
    public function __unserialize(array $data) : void {
        $this->id = $data['id'];
        $this->fetch(true);
    }


	/**
     * @return non-empty-string[]
	 */
    #[\Deprecated('Use the $rights property instead')]
    public function getRights() : array {
        return $this->rights;
	}

    /**
     * @param  non-empty-string  $right
     * @return bool
     */
	public function hasRight(string $right) : bool {
        // Check memo cache
        if (isset($this->hasRights[$right])) {
            return $this->hasRights[$right];
        }
        // Check user type
        if ($this->type->hasRight($right)) {
            $this->hasRights[$right] = true;
            return true;
        }
        // Check user rights
        $this->hasRights[$right] = in_array($right, $this->rights, true);
        return $this->hasRights[$right];
	}
}