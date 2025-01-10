<?php

namespace Lsr\Core\Auth\Models;

use Lsr\Db\DB;
use Lsr\Orm\Attributes\PrimaryKey;
use Lsr\Orm\Model;

#[PrimaryKey('id_user_type')]
class UserType extends Model
{

    public const string TABLE = 'user_types';
    public const string TYPE_RIGHTS_TABLE = 'user_type_rights';

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
            /** @var string[] $rights */
            $rights = DB::select($this::TYPE_RIGHTS_TABLE, 'right')
                        ->where('%n = %i', $this::getPrimaryKey(), $this->id)
                        ->fetchPairs();
            $this->rights = $rights;
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

        $test = DB::select($this::TYPE_RIGHTS_TABLE, 'COUNT(*)')
                  ->where('%n = %i AND [right] = %s', $this::getPrimaryKey(), $this->id, $right)
                  ->fetchSingle();
        $this->hasRights[$right] = $test > 0;
        return $this->hasRights[$right];
    }

}