<?php

namespace CasbinAdapter\Medoo;

use Casbin\Persist\Adapter as AdapterContract;
use Casbin\Persist\BatchAdapter as BatchAdapterContract;
use Casbin\Persist\UpdatableAdapter as UpdatableAdapterContract;
use Casbin\Persist\FilteredAdapter as FilteredAdapterContract;
use Casbin\Persist\AdapterHelper;
use Casbin\Model\Model;
use Medoo\Medoo;
use Casbin\Exceptions\CasbinException;
use Casbin\Persist\Adapters\Filter;
use Casbin\Exceptions\InvalidFilterTypeException;

/**
 * Medoo Adapter.
 *
 * @author techlee@qq.com
 */
class Adapter implements AdapterContract, BatchAdapterContract, UpdatableAdapterContract, FilteredAdapterContract
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
     * @var bool
     */
    private $filtered = false;

    /**
     * Adapter constructor.
     *
     * @param array $config
     */
    public function __construct(array $config)
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
    public static function newAdapter(array $config)
    {
        return new static($config);
    }

    /**
     * Returns true if the loaded policy has been filtered.
     *
     * @return bool
     */
    public function isFiltered(): bool
    {
        return $this->filtered;
    }

    /**
     * Sets filtered parameter.
     *
     * @param bool $filtered
     */
    public function setFiltered(bool $filtered): void
    {
        $this->filtered = $filtered;
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

    /**
     * savePolicyLine function.
     *
     * @param string $ptype
     * @param array  $rule
     *
     * @return void
     */
    public function savePolicyLine(string $ptype, array $rule): void
    {
        $data = [];
        foreach ($rule as $key => $value) {
            $data['v' . strval($key)] = $value;
        }

        $this->database->insert($this->casbinRuleTableName, $data);
    }

    /**
     * loads all policy rules from the storage.
     *
     * @param Model $model
     *
     * @return void
     */
    public function loadPolicy(Model $model): void
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
     * @return void
     */
    public function savePolicy(Model $model): void
    {
        foreach ($model['p'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }
        foreach ($model['g'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }
    }

    /**
     * adds a policy rule to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return void
     */
    public function addPolicy(string $sec, string $ptype, array $rule): void
    {
        $this->savePolicyLine($ptype, $rule);
    }

    /**
     * Adds a policy rules to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $rules
     */
    public function addPolicies(string $sec, string $ptype, array $rules): void
    {
        $cols = [];
        $i = 0;

        foreach ($rules as $rule) {
            $temp['ptype'] = $ptype;
            foreach ($rule as $key => $value) {
                $temp['v'. strval($key)] = $value;
            }
            $cols[$i++] = $temp ?? [];
            $temp = [];
        }
        $this->database->insert($this->casbinRuleTableName, $cols);
    }

    /**
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return void
     */
    public function removePolicy(string $sec, string $ptype, array $rule): void
    {
        $where['ptype'] = $ptype;

        foreach ($rule as $key => $value) {
            $where['v'.strval($key)] = $value;
        }

        $this->database->delete($this->casbinRuleTableName, ['AND' => $where]);
    }

    /**
     * Removes policy rules from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $rules
     */
    public function removePolicies(string $sec, string $ptype, array $rules): void
    {
        $this->database->action(function () use ($sec, $ptype, $rules) {
            foreach ($rules as $rule) {
                $this->removePolicy($sec, $ptype, $rule);
            }
        });
    }

    /**
     * RemoveFilteredPolicy removes policy rules that match the filter from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param int $fieldIndex
     * @param string ...$fieldValues
     *
     * @return void
     */
    public function removeFilteredPolicy(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): void
    {
        $where['ptype'] = $ptype;

        foreach (range(0, 5) as $value) {
            if ($fieldIndex <= $value && $value < $fieldIndex + count($fieldValues)) {
                if ('' != $val = $fieldValues[$value - $fieldIndex]) {
                    $where['v'.strval($value)] = $val;
                }
            }
        }

        $this->database->delete($this->casbinRuleTableName, ['AND' => $where]);
    }

    /**
     * Updates a policy rule from storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[] $oldRule
     * @param string[] $newPolicy
     */
    public function updatePolicy(string $sec, string $ptype, array $oldRule, array $newPolicy): void
    {
        $where = ['ptype' => $ptype];
        
        foreach ($oldRule as $k => $v) {
            $where['v' . strval($k)] = $v;
        }
        
        $columns = [];
        foreach ($newPolicy as $k => $v) {
            $columns['v' . strval($k)] = $v;
        }

        $this->database->update($this->casbinRuleTableName, $columns, $where);
    }

    /**
     * UpdatePolicies updates some policy rules to storage, like db, redis.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[][] $oldRules
     * @param string[][] $newRules
     * @return void
     */
    public function updatePolicies(string $sec, string $ptype, array $oldRules, array $newRules): void
    {
        $this->database->action(function () use ($sec, $ptype, $oldRules, $newRules) {
            foreach ($oldRules as $i => $oldRule) {
                $this->updatePolicy($sec, $ptype, $oldRule, $newRules[$i]);
            }
        });
    }

    /**
     * UpdateFilteredPolicies deletes old rules and adds new rules.
     *
     * @param string $sec
     * @param string $ptype
     * @param array $newPolicies
     * @param integer $fieldIndex
     * @param string ...$fieldValues
     * @return array
     */
    public function updateFilteredPolicies(string $sec, string $ptype, array $newPolicies, int $fieldIndex, string ...$fieldValues): array
    {
        $where['ptype'] = $ptype;
        foreach ($fieldValues as $fieldValue) {
            $suffix = $fieldIndex++;
            if (!is_null($fieldValue) && $fieldValue !== '') {
                $where['v'. $suffix] = $fieldValue;
            }
        }

        $newP = [];
        $oldP = [];
        foreach ($newPolicies as $newRule) {
            $col['ptype'] = $ptype;
            foreach ($newRule as $key => $value) {
                $col['v' . strval($key)] = $value;
            }
            $newP[] = $col;
        }

        $this->database->action(function () use ($newP, $where, &$oldP) {
            $columns = ['ptype', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5'];
            $oldP = $this->database->select($this->casbinRuleTableName, $columns, $where);

            foreach ($oldP as &$item) {
                $item = array_filter($item, function ($value) {
                    return !is_null($value) && $value !== '';
                });
                unset($item['ptype']);
            }

            $this->database->delete($this->casbinRuleTableName, ['AND' => $where]);
            $this->database->insert($this->casbinRuleTableName, $newP);
        });

        // return deleted rules
        return $oldP;
    }

    /**
     * Loads only policy rules that match the filter.
     *
     * @param Model $model
     * @param mixed $filter
     */
    public function loadFilteredPolicy(Model $model, $filter): void
    {
        $columns = ['ptype', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5'];
        if (is_string($filter)) {
            $where = Medoo::raw('WHERE ' . $filter);
            $rows = $this->database->select($this->casbinRuleTableName, $columns, $where);
        } elseif ($filter instanceof Filter) {
            foreach ($filter->p as $k => $v) {
                $where[$v] = $filter->g[$k];
            }
            $rows = $this->database->select($this->casbinRuleTableName, $columns, $where);
        } elseif ($filter instanceof \Closure) {
            $rows = [];
            $filter($this->database, $this->casbinRuleTableName, $columns, $rows);
        } else {
            throw new InvalidFilterTypeException('invalid filter type');
        }

        foreach ($rows as $row) {
            $row = array_filter($row, function ($value) {
                return !is_null($value) && $value !== '';
            });
            $line = implode(', ', array_filter($row, function ($val) {
                return '' != $val && !is_null($val);
            }));
            $this->loadPolicyLine(trim($line), $model);
        }
        $this->setFiltered(true);
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
