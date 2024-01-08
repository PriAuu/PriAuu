<?php
class User_model extends CI_Model
{
    public function addUser($d)
    {
        $string = array(
            'firstname' => $d['firstname'],
            'lastname' => $d['lastname'],
            'email' => $d['email'],
            'password' => $d['password'],
            'role' => $d['role'],
            'status' => $d['status'],
            'banned_users' => $d['banned_users']
        );
        $q = $this->db->insert_string('users', $string);
        $this->db->query($q);
        return $this->db->insert_id();
    }
}