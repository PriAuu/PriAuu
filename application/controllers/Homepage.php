<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Homepage extends CI_Controller
{
    
    public function index()
    {
        $this->load->view('navbar');
        $this->load->view('homepage');
    }
}
