<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class EnsureFrontendRequestsAreStateful
{
    public function handle(Request $request, Closure $next)
    {
        if ($this->shouldPassThrough($request)) {
            return $next($request);
        }

        if (!$request->headers->has('X-XSRF-TOKEN')) {
            return response()->json(['message' => 'CSRF token mismatch'], 419);
        }

        $token = urldecode($request->headers->get('X-XSRF-TOKEN'));
        $request->headers->set('X-CSRF-TOKEN', $token);

        return $next($request);
    }

    protected function shouldPassThrough($request)
    {
        return $request->isMethod('GET') ||
               $request->is('api/auth/login') ||
               $request->is('api/auth/refresh') ||
               $request->is('api/auth/csrf-token');
    }
}
