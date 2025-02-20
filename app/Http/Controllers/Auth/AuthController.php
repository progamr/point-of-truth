<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Services\JwtService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    private JwtService $jwtService;

    public function __construct(JwtService $jwtService)
    {
        $this->jwtService = $jwtService;
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if (!Auth::attempt($credentials)) {
            return response()->json([
                'message' => 'Invalid credentials'
            ], 401);
        }

        $user = Auth::user();
        return $this->jwtService->createTokenResponse($user);
    }

    public function me(Request $request)
    {
        $token = str_replace('Bearer ', '', $request->header('Authorization'));
        
        if (empty($token) || !$this->jwtService->validateToken($token)) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        $user = $this->jwtService->getUserFromToken($token);
        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        return response()->json($user);
    }

    public function logout(Request $request)
    {
        Auth::guard('api')->logout();
        return response()->json(['message' => 'Successfully logged out']);
    }

    public function getCsrfToken()
    {
        return response()->json([
            'token' => csrf_token()
        ])->withCookie(
            'XSRF-TOKEN',
            csrf_token(),
            60 * 24,
            '/',
            env('SESSION_DOMAIN'),
            env('APP_ENV') === 'production',
            true,
            false,
            'Lax'
        );
    }
}
