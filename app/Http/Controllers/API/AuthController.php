<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\RefreshToken;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    /**
     * Login user & issue Sanctum token
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        if($validator->fails()){
            return response()->json([
                'success' => false,
                'message' => 'Validation error',
                'error' => $validator->errors()
            ], 400);
        }

        $user = User::where('email', $request->email)->first();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            return response()->json([
                'success' => false,
                'message' => 'Login failed.',
                'error' => 'The provided credentials are incorrect.'
            ]);
        }

        // Optional: revoke old tokens (single session)
        $user->tokens()->delete();

        $accessToken = $user->createToken(
            'access-token',
            ['*'],
            now()->addMinutes(10)
        );

        $refreshTokenPlain = \Str::random(64);

        $refreshToken =  RefreshToken::create([
            'user_id' => $user->id,
            'token_hash' => hash('sha256', $refreshTokenPlain),
            'expires_at' => now()->addDays(7),
        ]);


        return response()->json([
            'success' => true,
            'message' => 'Login successful',
            'data' => [
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                ],
                'access_token' => $accessToken->plainTextToken,
                'access_expires_at' => $accessToken->accessToken->expires_at->format('Y-m-d H:i:s'),
                'refresh_token' => $refreshTokenPlain,
                'refresh_expires_at' => $refreshToken->expires_at->format('Y-m-d H:i:s')
            ],
        ]);
    }

    /**
     * Register new user (optional)
     */
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = $user->createToken('api-token');

        return response()->json([
            'success' => true,
            'message' => 'Register successful',
            'data' => [
                'user' => $user,
                'access_token' => $token->plainTextToken,
            ],
        ], 201);
    }

    /**
     * Logout (revoke current token)
     */
    public function logout(Request $request)
    {
        $user = $request->user();

        // 1️⃣ revoke access token yang sedang dipakai
        $user->currentAccessToken()?->delete();

        // 2️⃣ revoke refresh token PASANGAN
        if ($request->refresh_token) {
            RefreshToken::where('token_hash', hash('sha256', $request->refresh_token))
                ->update(['revoked_at' => now()]);
        }

        return response()->json([
            'success' => true,
            'message' => 'Logged out',
        ]);
    }

    public function refresh(Request $request)
    {
        $refreshTokenPlain = $request->bearerToken();

        $refreshToken = RefreshToken::where('token_hash', hash('sha256', $refreshTokenPlain))
            ->whereNull('revoked_at')
            ->where('expires_at', '>', now())
            ->first();

        if (!$refreshToken) {
            return response()->json([
                'message' => 'Invalid refresh token'
            ], 401);
        }

        $user = $refreshToken->user;

        // ROTATION
        $refreshToken->update(['revoked_at' => now()]);

        $newAccessToken = $user->createToken(
            'access-token',
            ['*'],
            now()->addMinutes(10)
        );

        $newRefreshPlain = \Str::random(64);

        $refreshToken = RefreshToken::create([
            'user_id' => $user->id,
            'token_hash' => hash('sha256', $newRefreshPlain),
            'expires_at' => now()->addDays(7),
        ]);

        return response()->json([
            'access_token' => $newAccessToken->plainTextToken,
            'access_expires_at' => $newAccessToken->accessToken->expires_at->format('Y-m-d H:i:s'),
            'refresh_token' => $newRefreshPlain,
            'refresh_expires_at' => $refreshToken->expires_at->format('Y-m-d H:i:s')
        ]);
    }

}
