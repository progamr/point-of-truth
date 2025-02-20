<?php

namespace App\Guards;

use App\Services\JwtService;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;

class JwtGuard implements Guard
{
    use GuardHelpers;

    protected $request;
    protected $jwtService;

    public function __construct(UserProvider $provider, JwtService $jwtService, Request $request)
    {
        $this->provider = $provider;
        $this->jwtService = $jwtService;
        $this->request = $request;
    }

    public function user()
    {
        if (!is_null($this->user)) {
            \Log::info('Using cached user');
            return $this->user;
        }

        $token = $this->getTokenFromRequest();

        if (!$token) {
            \Log::warning('No token found in request');
            return null;
        }

        \Log::info('Validating token', ['token' => substr($token, 0, 10) . '...']);

        if (!$this->jwtService->validateToken($token)) {
            \Log::error('Token validation failed');
            return null;
        }

        $this->user = $this->jwtService->getUserFromToken($token);
        if (!$this->user) {
            \Log::error('User not found for token');
            return null;
        }

        \Log::info('User authenticated successfully', ['user_id' => $this->user->id]);
        return $this->user;
    }

    protected function getTokenFromRequest()
    {
        $header = $this->request->header('Authorization', '');
        \Log::info('Authorization header', ['header' => $header]);
        
        if (str_starts_with($header, 'Bearer ')) {
            $token = substr($header, 7);
            \Log::info('Extracted token', ['token' => substr($token, 0, 10) . '...']);
            return $token;
        }
        
        \Log::warning('No Bearer token found in Authorization header');
        return null;
    }

    public function validate(array $credentials = [])
    {
        return (bool) $this->attempt($credentials, false);
    }

    public function attempt(array $credentials = [], $login = true)
    {
        $user = $this->provider->retrieveByCredentials($credentials);

        if ($user && $this->provider->validateCredentials($user, $credentials)) {
            if ($login) {
                $this->setUser($user);
            }
            return true;
        }

        return false;
    }
}
