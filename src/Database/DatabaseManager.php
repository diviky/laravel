<?php

declare(strict_types=1);

namespace Diviky\Bright\Database;

use Diviky\Bright\Database\Concerns\Connector;
use Illuminate\Database\DatabaseManager as LaravelDatabaseManager;

class DatabaseManager extends LaravelDatabaseManager
{
    use Connector;

    /**
     * Database table.
     *
     * @param  string  $name
     * @return \Illuminate\Database\Query\Builder
     */
    public function table($name)
    {
        $alias = '';
        if (\stripos($name, ' as ') !== false) {
            $segments = \preg_split('/\s+as\s+/i', $name);
            $alias = ' as ' . $segments[1];
            $name = $segments[0];
        }

        return $this->getConnectionByTable($name)->table($name . $alias);
    }

    /**
     * Get a database connection instance.
     *
     * @return \Illuminate\Database\Connection
     */
    protected function getConnectionByTable(string $name)
    {
        [$connection, $config] = $this->getConnectionDetails($name);

        $connection = $this->connection($connection);
        $connection->getQueryGrammar()->setConfig($config);

        return $connection;
    }

    /**
     * Get the configuration for a connection.
     *
     * @param  string  $name
     * @return array
     *
     * @throws \InvalidArgumentException
     */
    protected function configuration($name)
    {
        $config = parent::configuration($name);

        $config['bright'] = $this->getBrightConfig();

        return $config;
    }
}
