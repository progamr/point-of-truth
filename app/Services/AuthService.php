<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthService
{
    private JwtService $jwtService;

    public function __construct(JwtService $jwtService)
    {
        $this->jwtService = $jwtService;
    }

    /**
     * Register a new user
     *
     * @param array $data
     * @return array
     */
    public function register(array $data): array
    {
        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
        ]);

        return $this->generateAuthResponse($user);
    }

    /**
     * Authenticate a user
     *
     * @param array $credentials
     * @return array
     * @throws ValidationException
     */
    public function login(array $credentials): array
    {
        if (!Auth::attempt($credentials)) {
            throw ValidationException::withMessages([
                'email' => ['Invalid credentials'],
            ]);
        }

        $user = Auth::user();
        return $this->generateAuthResponse($user);
    }

    /**
     * Get authenticated user
     *
     * @param string $token
     * @return User|null
     */
    public function getAuthenticatedUser(string $token): ?User
    {
        if (empty($token) || !$this->jwtService->validateToken($token)) {
            return null;
        }

        return $this->jwtService->getUserFromToken($token);
    }

    /**
     * Logout the user
     *
     * @return void
     */
    public function logout(): void
    {
        Auth::guard('api')->logout();
    }

    /**
     * Generate authentication response with token
     *
     * @param User $user
     * @return array
     */
    private function generateAuthResponse(User $user): array
    {
        $tokenData = $this->jwtService->createToken($user);

        return [
            'user' => $user,
            'access_token' => $tokenData['access_token'],
            'token_type' => $tokenData['token_type'],
            'expires_in' => $tokenData['expires_in']
        ];
    }
}
