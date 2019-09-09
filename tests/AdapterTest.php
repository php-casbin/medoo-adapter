<?php

namespace CasbinAdapter\Medoo\Tests;

use Casbin\Enforcer;
use Casbin\Model\Model;
use CasbinAdapter\Medoo\Adapter as DatabaseAdapter;
use PHPUnit\Framework\TestCase;

class AdapterTest extends TestCase
{
    protected $config = [];

    protected function initConfig()
    {
        $this->config = [
            'database_type' => 'mysql',
            'server' => $this->env('DB_PORT', '127.0.0.1'),
            'database_name' => $this->env('DB_DATABASE', 'casbin'),
            'username' => $this->env('DB_USERNAME', 'root'),
            'password' => $this->env('DB_PASSWORD', ''),
            'port' => $this->env('DB_PORT', 3306),
        ];
    }

    protected function initDb(DatabaseAdapter $adapter)
    {
        $tableName = $adapter->casbinRuleTableName;
        $database = $adapter->getDatabase();

        $database->delete($tableName, []);

        $data = [
            ['ptype' => 'p', 'v0' => 'alice', 'v1' => 'data1', 'v2' => 'read'],
            ['ptype' => 'p', 'v0' => 'bob', 'v1' => 'data2', 'v2' => 'write'],
            ['ptype' => 'p', 'v0' => 'data2_admin', 'v1' => 'data2', 'v2' => 'read'],
            ['ptype' => 'p', 'v0' => 'data2_admin', 'v1' => 'data2', 'v2' => 'write'],
            ['ptype' => 'g', 'v0' => 'alice', 'v1' => 'data2_admin', 'v2' => null],
        ];

        $database->insert($tableName, $data);
    }

    protected function getEnforcer()
    {
        $this->initConfig();
        $adapter = DatabaseAdapter::newAdapter($this->config);

        $this->initDb($adapter);
        $model = Model::newModelFromString(
            <<<'EOT'
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
EOT
        );

        return new Enforcer($model, $adapter);
    }

    public function testLoadPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
    }

    public function testAddPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('eve', 'data3', 'read'));

        $e->addPermissionForUser('eve', 'data3', 'read');
        $this->assertTrue($e->enforce('eve', 'data3', 'read'));
    }

    public function testSavePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('alice', 'data4', 'read'));

        $model = $e->getModel();
        $model->clearPolicy();
        $model->addPolicy('p', 'p', ['alice', 'data4', 'read']);

        $adapter = $e->getAdapter();
        $adapter->savePolicy($model);
        $this->assertTrue($e->enforce('alice', 'data4', 'read'));
    }

    public function testRemovePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
        $e->addPermissionForUser('alice', 'data5', 'read');
        $this->assertTrue($e->enforce('alice', 'data5', 'read'));
        $e->deletePermissionForUser('alice', 'data5', 'read');
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
    }

    public function testRemoveFilteredPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $e->removeFilteredPolicy(1, 'data1');
        $this->assertFalse($e->enforce('alice', 'data1', 'read'));

        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));

        $e->removeFilteredPolicy(1, 'data2', 'read');

        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));

        $e->removeFilteredPolicy(2, 'write');

        $this->assertFalse($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));
    }

    protected function env($key, $default = null)
    {
        $value = getenv($key);
        if (is_null($default)) {
            return $value;
        }

        return false === $value ? $default : $value;
    }
}
