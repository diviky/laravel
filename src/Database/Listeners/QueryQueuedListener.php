<?php

declare(strict_types=1);

namespace Diviky\Bright\Database\Listeners;

use Diviky\Bright\Database\Events\QueryQueued as QueryQueuedEvent;
use Diviky\Bright\Database\Jobs\Statement;

class QueryQueuedListener
{
    /**
     * Handle the event.
     */
    public function handle(QueryQueuedEvent $event): void
    {
        $async = $event->async;

        Statement::dispatch($event->sql, base64_encode(serialize($event->bindings)), 2)
            ->onConnection($async[0])
            ->onQueue($async[1]);
    }
}
