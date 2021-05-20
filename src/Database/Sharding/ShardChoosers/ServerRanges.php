<?php

namespace Diviky\Bright\Database\Sharding\ShardChoosers;

use Diviky\Bright\Database\Sharding\Exceptions\ShardingException;

class ServerRanges implements ShardChooserInterface
{
    /**
     * Set the connections.
     *
     * @var array
     */
    protected $connections = [];

    /**
     * @param array  $connections
     * @param string $relationKey
     */
    public function __construct($connections, $relationKey = null)
    {
        $this->connections = $connections;
        unset($relationKey);
    }

    /**
     * {@inheritDoc}
     *
     * @throws ShardingException
     */
    public function getShardById($id)
    {
        foreach ($this->connections as $shard => $range) {
            if ($id >= $range[0] && $id <= $range[1]) {
                return $shard;
            }
        }

        throw new ShardingException('Your must to set up range for this id!');
    }

    /**
     * {@inheritDoc}
     */
    public function chooseShard($id)
    {
        return $this->getShardById($id);
    }

    /**
     * {@inheritDoc}
     */
    public function setRelation($id, $shard): bool
    {
        return true;
    }
}