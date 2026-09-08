<?php

declare(strict_types=1);

namespace TestCases;

use Dibi\Connection as DibiConnection;
use Lsr\Caching\Cache;
use Lsr\Core\Auth\Models\UserType;
use Lsr\Db\Connection;
use Lsr\Db\DB;
use Lsr\Serializer\Mapper;
use Nette\Caching\Storages\DevNullStorage;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionProperty;
use Symfony\Component\Serializer\Serializer;

final class UserTypeRightsTest extends TestCase
{
    public function test_rights_are_loaded_lazily_and_empty_results_are_cached(): void {
        $config = ['driver' => 'pdo', 'dsn' => 'sqlite::memory:'];
        $connection = new Connection(new Cache(new DevNullStorage()), new Mapper(new Serializer()), $config);
        $connection->connection = new DibiConnection($config);
        $connection->query('CREATE TABLE user_type_rights (id_user_type INTEGER, [right] TEXT)');
        $connection->query("INSERT INTO user_type_rights VALUES (1, 'users.read'), (3, 'users.write')");

        $db = new ReflectionProperty(DB::class, 'db');
        $previousConnection = $db->getValue();
        $db->setValue(null, $connection);
        try {
            $type = (new ReflectionClass(RightsTestUserType::class))->newInstanceWithoutConstructor();
            $type->id = 1;
            self::assertSame(['users.read'], $type->getRights());
            self::assertTrue($type->hasRight('users.read'));
            self::assertFalse($type->hasRight('users.write'));

            $emptyType = (new ReflectionClass(RightsTestUserType::class))->newInstanceWithoutConstructor();
            $emptyType->id = 2;
            self::assertSame([], $emptyType->getRights());

            $connection->query('DELETE FROM user_type_rights WHERE id_user_type = 1');
            $connection->query("INSERT INTO user_type_rights VALUES (2, 'users.read')");
            self::assertSame(['users.read'], $type->getRights());
            self::assertSame([], $emptyType->getRights());
        } finally {
            $db->setValue(null, $previousConnection);
        }
    }
}

final class RightsTestUserType extends UserType
{
    public static function getPrimaryKey(): string {
        return 'id_user_type';
    }
}
