<?php namespace App\Controllers;
 
use CodeIgniter\RESTful\ResourceController;
use CodeIgniter\API\ResponseTrait;
use App\Models\UserModel;
use \Firebase\JWT\JWT;

class Login extends ResourceController
{
     use ResponseTrait;
    public function index()
    {
        $email             = $this->request->getVar('email');
        $password          = $this->request->getVar('password');

         $userModel = new UserModel;
         $user = $userModel->where('email', $email)->first(); 

         if(!$user) {
            return $this->respond(['status' => false, 'message' => 'Username atau Password salah'], 401);
         }
        
         if(!password_verify($password, $user['password'])) {
            return $this->respond(['status' => false, 'message' => 'Username atau Password salah'], 401);
          }

         $key = getenv('TOKEN_SECRET');

         $iat = time();

         $exp = $iat + (60*3);

         $payload = array(
            "iss" => "Issuer of the JWT",
            "aud" => "Audience that the JWT",
            "sub" => "Subject of the JWT",
            "iat" => $iat, //Time the JWT issued at
            "exp" => $exp, // Expiration time of token
            "email" => $user['email'],
        );

           $token = JWT::encode($payload, $key, "HS256");
            return $this->respond(['status' => true, 'token' => $token], 200);
    }

}