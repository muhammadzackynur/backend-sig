<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator; // Tambahkan import ini
use Illuminate\Support\Str;
use Google_Client;

class LoginController extends Controller
{
    // 1. Fungsi untuk Register Manual
    public function register(Request $request)
    {
        // Validasi input dari Flutter
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'phone_number' => 'nullable|string',
            'password' => 'required|string|min:8', 
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => $validator->errors()->first()
            ], 400); 
        }

        // Simpan user ke database MySQL
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'phone_number' => $request->phone_number,
            'password' => Hash::make($request->password), // Password dienkripsi
        ]);

        // Generate token Sanctum
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'status' => 'success',
            'message' => 'Pendaftaran Berhasil!',
            'access_token' => $token,
            'token_type' => 'Bearer',
            'user' => $user
        ], 201); 
    }

    // 2. Fungsi untuk Login Manual
    public function login(Request $request)
    {
        // Validasi input
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => $validator->errors()->first()
            ], 400);
        }

        // Cari user berdasarkan email
        $user = User::where('email', $request->email)->first();

        // Cek kecocokan password
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'Email atau Password salah.'
            ], 401);
        }

        // Generate token Sanctum
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'status' => 'success',
            'message' => 'Login Berhasil!',
            'access_token' => $token,
            'token_type' => 'Bearer',
            'user' => $user
        ], 200);
    }

    // 3. Fungsi untuk Login/Signup via Google
    public function googleAuth(Request $request)
    {
        $request->validate([
            'id_token' => 'required|string',
            'phone_number' => 'nullable|string' // Dikirim dari Flutter jika user menginputnya
        ]);

        // Inisialisasi Google Client
        $client = new Google_Client(['client_id' => env('GOOGLE_CLIENT_ID')]); 
        $payload = $client->verifyIdToken($request->id_token);

        if ($payload) {
            // Cek apakah user sudah ada berdasarkan email
            $user = User::where('email', $payload['email'])->first();

            if (!$user) {
                // Proses SIGNUP: Buat user baru jika belum ada
                $user = User::create([
                    'name' => $payload['name'],
                    'email' => $payload['email'],
                    'phone_number' => $request->phone_number ?? null,
                    // Generate password acak karena Google tidak mengirimkan password
                    'password' => Hash::make(Str::random(24)),
                ]);
            } else {
                // Opsional: Update nomor telepon jika user login lagi dan sebelumnya nomornya kosong
                if ($request->phone_number && !$user->phone_number) {
                    $user->update(['phone_number' => $request->phone_number]);
                }
            }

            // Buat token Sanctum untuk otentikasi API selanjutnya
            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'status' => 'success',
                'message' => 'Berhasil login dengan Google',
                'access_token' => $token,
                'token_type' => 'Bearer',
                'user' => $user
            ]);
        } else {
            return response()->json(['message' => 'Token Google tidak valid'], 401);
        }
    }
}