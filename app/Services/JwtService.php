<?php

namespace App\Services;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use DateTimeImmutable;
use App\Models\User;
use Illuminate\Http\JsonResponse;

class JwtService
{
    private Configuration $config;

    public function __construct()
    {
        $this->config = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::base64Encoded(env('JWT_SECRET'))
        );
    }

    public function createTokenResponse(User $user): JsonResponse
    {
        $token = $this->createToken($user);
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => 900 // 15 minutes in seconds
        ]);
    }

    private function createToken(User $user): string
    {
        $now = new DateTimeImmutable();

        $token = $this->config->builder()
            ->issuedBy(config('app.url'))
            ->permittedFor(config('app.url'))
            ->identifiedBy($user->id)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->modify('+15 minutes'))
            ->withClaim('user_id', $user->id)
            ->withClaim('email', $user->email)
            ->withClaim('csrf', csrf_token())
            ->getToken($this->config->signer(), $this->config->signingKey());

        return $token->toString();
    }

    public function validateToken(string $token): bool
    {
        try {
            $parsedToken = $this->config->parser()->parse($token);
            $now = new DateTimeImmutable();
            
            // Verify token signature
            if (!$this->config->validator()->validate($parsedToken, new \Lcobucci\JWT\Validation\Constraint\SignedWith(
                $this->config->signer(),
                $this->config->signingKey()
            ))) {
                \Log::error('JWT validation failed: Invalid signature');
                return false;
            }
            
            // Check if token has expired
            $exp = $parsedToken->claims()->get('exp');
            if ($exp instanceof DateTimeImmutable) {
                $exp = $exp->getTimestamp();
            }
            if ($exp < $now->getTimestamp()) {
                \Log::error('JWT validation failed: Token has expired', [
                    'exp' => $exp,
                    'now' => $now->getTimestamp()
                ]);
                return false;
            }
            
            // Log successful validation
            \Log::info('JWT validation successful', [
                'user_id' => $parsedToken->claims()->get('user_id'),
                'email' => $parsedToken->claims()->get('email')
            ]);
            
            return true;
        } catch (\Exception $e) {
            \Log::error('JWT validation failed: ' . $e->getMessage(), [
                'exception' => get_class($e),
                'trace' => $e->getTraceAsString()
            ]);
            return false;
        }
    }

    public function getUserFromToken(string $token)
    {
        try {
            $parsedToken = $this->config->parser()->parse($token);
            $userId = $parsedToken->claims()->get('user_id');
            return User::find($userId);
        } catch (\Exception $e) {
            return null;
        }
    }
}
