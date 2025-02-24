<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\RegisterRequest;
use App\Services\AuthService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    private AuthService $authService;

    public function __construct(AuthService $authService)
    {
        $this->authService = $authService;
    }

    /**
     * Register a new user
     *
     * @param RegisterRequest $request
     * @return JsonResponse
     */
    public function register(RegisterRequest $request): JsonResponse
    {
        $authData = $this->authService->register($request->validated());
        return $this->sendAuthResponse($authData);
    }

    /**
     * Login user
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function login(LoginRequest $request): JsonResponse
    {
        try {
            $authData = $this->authService->login($request->validated());
            return $this->sendAuthResponse($authData);
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Invalid credentials',
            ], 401);
        }
    }

    /**
     * Get authenticated user
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function me(Request $request): JsonResponse
    {
        $token = str_replace('Bearer ', '', $request->header('Authorization'));
        $user = $this->authService->getAuthenticatedUser($token);

        if (!$user) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        return response()->json($user);
    }

    /**
     * Logout user
     *
     * @return JsonResponse
     */
    public function logout(): JsonResponse
    {
        $this->authService->logout();
        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Get CSRF token
     *
     * @return JsonResponse
     */
    public function getCsrfToken(): JsonResponse
    {
        return $this->sendAuthResponse([
            'token' => csrf_token()
        ], true);
    }

    /**
     * Send a standardized authentication response
     *
     * @param array $data
     * @param bool $withCsrfCookie
     * @return JsonResponse
     */
    private function sendAuthResponse(array $data, bool $withCsrfCookie = false): JsonResponse
    {
        $response = response()->json($data);

        if ($withCsrfCookie) {
            $response->withCookie(
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

        return $response;
    }
}
