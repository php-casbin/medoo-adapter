<?php

namespace CasbinAdapter\Medoo;

use Casbin\Persist\Adapter as AdapterContract;
use Casbin\Persist\AdapterHelper;
use Casbin\Model\Model;
use Medoo\Medoo;

/**
 * Medoo Adapter.
 *
 * @author techlee@qq.com
 */
class Adapter implements AdapterContract
{
    use AdapterHelper;

    /**
     * Medoo instance.
     *
     * @var \Medoo\Medoo
     */
    protected $database;

    /**
     * CasbinRule table name.
     *
     * @var string
     */
    public $casbinRuleTableName = 'casbin_rule';

    /**
     * Adapter constructor.
     *
     * @param array $config
     */
    public function __construct($config)
    {
        $database = new Medoo($config);
        $this->database = $database;

        $this->initTable();
    }

    /**
     * New a Adapter.
     *
     * @param array $config
     *
     * @return Adapter
     */
    public static function newAdapter($config)
    {
        return new static($config);
    }

    /**
     * Initialize the policy rules table, create if it does not exist.
     *
     * @return void
     */
    public function initTable()
    {
        $this->database->create($this->casbinRuleTableName, [
            'ptype' => ['VARCHAR(255)'],
            'v0' => ['VARCHAR(255)'],
            'v1' => ['VARCHAR(255)'],
            'v2' => ['VARCHAR(255)'],
            'v3' => ['VARCHAR(255)'],
            'v4' => ['VARCHAR(255)'],
            'v5' => ['VARCHAR(255)'],
        ]);
    }

    public function savePolicyLine($ptype, array $rule)
    {
        $data = [];
        foreach ($rule as $key => $value) {
            $data['v'.strval($key)] = $value;
        }

        return $this->database->insert($this->casbinRuleTableName, $data);
    }

    /**
     * loads all policy rules from the storage.
     *
     * @param Model $model
     */
    public function loadPolicy($model)
    {
        $data = $this->database->select($this->casbinRuleTableName, ['ptype', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5']);
        foreach ($data as $row) {
            $line = implode(', ', array_filter($row, function ($val) {
                return '' != $val && !is_null($val);
            }));
            $this->loadPolicyLine(trim($line), $model);
        }
    }

    /**
     * saves all policy rules to the storage.
     *
     * @param Model $model
     *
     * @return bool
     */
    public function savePolicy($model)
    {
        foreach ($model->model['p'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }
        foreach ($model->model['g'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }

        return true;
    }

    /**
     * adds a policy rule to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return mixed
     */
    public function addPolicy($sec, $ptype, $rule)
    {
        return $this->savePolicyLine($ptype, $rule);
    }

    /**
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return mixed
     */
    public function removePolicy($sec, $ptype, $rule)
    {
        $where['ptype'] = $ptype;

        foreach ($rule as $key => $value) {
            $where['v'.strval($key)] = $value;
        }

        return $this->database->delete($this->casbinRuleTableName, ['AND' => $where]);
    }

    /**
     * RemoveFilteredPolicy removes policy rules that match the filter from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param int    $fieldIndex
     * @param mixed  ...$fieldValues
     *
     * @return mixed
     */
    public function removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues)
    {
        $where['ptype'] = $ptype;

        foreach (range(0, 5) as $value) {
            if ($fieldIndex <= $value && $value < $fieldIndex + count($fieldValues)) {
                if ('' != $val = $fieldValues[$value - $fieldIndex]) {
                    $where['v'.strval($value)] = $val;
                }
            }
        }

        return $this->database->delete($this->casbinRuleTableName, ['AND' => $where]);
    }

    /**
     * Gets database.
     *
     * @return \Medoo\Medoo
     */
    public function getDatabase()
    {
        return $this->database;
    }
}
