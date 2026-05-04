<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        // 1. Validasi input dari Flutter (hanya butuh email dan password)
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => $validator->errors()
            ], 422);
        }

        // 2. Cek apakah email dan password cocok dengan yang ada di database
        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json([
                'status' => 'error',
                'message' => 'Email atau Password salah.'
            ], 401);
        }

        // 3. Ambil data user yang berhasil login
        $user = User::where('email', $request->email)->firstOrFail();

        // 4. Buatkan token Sanctum untuk user tersebut
        $token = $user->createToken('auth_token')->plainTextToken;

        // 5. Kembalikan response sukses beserta tokennya ke Flutter
        return response()->json([
            'status' => 'success',
            'message' => 'Login berhasil!',
            'data' => $user,
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }
}