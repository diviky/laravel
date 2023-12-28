<?php

declare(strict_types=1);

namespace Diviky\Bright\Http\Middleware;

class Ajax
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    public function handle($request, \Closure $next)
    {
        if ($request->input('_request') == 'iframe') {
            $request->headers->add(['Accept' => 'application/json']);
        }

        return $next($request);
    }
}
