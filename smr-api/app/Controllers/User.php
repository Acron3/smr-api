<?php namespace App\Controllers;
 
use CodeIgniter\RESTful\ResourceController;
use CodeIgniter\API\ResponseTrait;
use App\Models\UserModel;
use Firebase\JWT\JWT;

class User extends ResourceController
{
    use ResponseTrait;
    // get all user
    public function index()
    {
        $model = new UserModel();
        $data = $model->orderBy('id', 'DESC')->findAll();
        return $this->respond($data);
    }
 
    // get single user
    public function show($id = null)
    {
        $model = new UserModel();
        $data = $model->getWhere(['id' => $id])->getResult();
        if($data){
            return $this->respond($data);
        }else{
            return $this->failNotFound('No Data Found with id '.$id);
        }
    }
 
    // create a user
    public function create()
    {
        $model = new UserModel();
        //include helper form
        helper(['form']);
        //set rules validation form
        $rules = [
            'nama'          => 'required|min_length[3]',
            'email'         => 'required|min_length[6]|max_length[50]|valid_email|is_unique["email"]',
            'username'      => 'required|min_length[6]|max_length[50]|is_unique["username"]',
            'no_handphone'  => 'required|min_length[12]|max_length[13]',
            'password'      => 'required|min_length[6]|max_length[200]',
            'confpassword'  => 'matches[password]'
        ];

        if($this->validate($rules)){
            $data = [
                'nama'              => $this->request->getVar('nama'),
                'username'          => $this->request->getVar('username'),
                'email'             => $this->request->getVar('email'),
                'no_handphone'      => $this->request->getVar('no_handphone'),
                'password'          => password_hash($this->request->getVar('password'), PASSWORD_DEFAULT)
            ];
            
            $registered = $model->save($data);
            $this->respondCreated($registered);
        }else{
            return $this->fail($this->validator->getErrors());
        }
    }
 
    // update user
    public function update($id = null)
    {
        $model = new UserModel();
        $json = $this->request->getJSON();
        if($json){
            $data = [
                'nama' => $json->nama,
                'username' => $json->username,
                'email' => $json->email,
                'password' => password_hash($json->password,PASSWORD_DEFAULT),
                'no_handphone' => $json->no_handphone
            ];
        }else{
            $input = $this->request->getRawInput();
            $data = [
                'nama' => $input['nama'],
                'username' => $input['username'],
                'email' => $input['email'],
                'password' => password_hash($input['password'],PASSWORD_DEFAULT),
                'no_handphone' => $input['no_handphone']
            ];
        }
        // Insert to Database
        $model->update($id, $data);
        $response = [
            'status'   => 200,
            'error'    => null,
            'messages' => [
                'success' => 'Data Updated'
            ]
        ];
        return $this->respond($response);
    }
 
    // delete user
    public function delete($id = null)
    {
        $model = new UserModel();
        $data = $model->find($id);
        if($data){
            $model->delete($id);
            $response = [
                'status'   => 200,
                'error'    => null,
                'messages' => [
                    'success' => 'Data Deleted'
                ]
            ];
             
            return $this->respondDeleted($response);
        }else{
            return $this->failNotFound('No Data Found with id '.$id);
        }
         
    }
    
    public function login()
    {
        $model = new UserModel();
         $data = [
            'username' => $this->request->getVar('username'),
            'password' => $this->request->getVar('password'),
        ];
        $result = $model->getWhere(['username' => $data['username']])->getResult();
        if(!empty($result)){
            if(password_verify($data['password'], $result[0]->password)){
                $key = getenv('TOKEN_SECRET');
                $payload = array(
                    "iat" => 1356999524,
                    "nbf" => 1357000000,
                    "uid" => $result[0]->id,
                    "email" => $result[0]->email
                );
                $token = JWT::encode($payload, $key, 'HS256');
        
                return $this->respond($token);
            }else{
                return $this->failUnauthorized("Username atau Password Salah");
            }
        }else{
            return $this->failUnauthorized('Username atau Password Salah');
        }
    }
 
}