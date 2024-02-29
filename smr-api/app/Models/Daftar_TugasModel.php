<?php

namespace App\Models;

use CodeIgniter\Model;

class Daftar_TugasModel extends Model
{
    
    protected $table            = 'daftar_tugas';
    protected $primaryKey       = 'no';
    protected $useAutoIncrement = true;
    protected $returnType       = 'array';
    protected $useSoftDeletes   = false;
    protected $protectFields    = true;
    protected $allowedFields    = ['no','nama_kegiatan','target','tanggal_mulai','deadline','status'];

   
}
