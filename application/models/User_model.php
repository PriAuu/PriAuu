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

  public function checklogin($post)
  {
    $this->load->library('password');
    $this->db->select('*');
    $this->db->where('email', $post['email']);
    $query = $this->db->get('users');
    $userInfo = $query->row();
    $count = $query->num_rows();

    if ($count == 1) {
      if (!$this->password->validate_password($post['password'], $userInfo->password)) {
        error_log('Unsuccessful login attempt(' . $post['email'] . ')');
        return false;
      }
    } else {
      error_log('Unsuccessful login attempt(' . $post['email'] . ')');
      return false;
    }

    unset($userInfo->password);
    return $userInfo;
  }
  public function getAllSettings()
  {
    $this->db->select('*');
    $this->db->from('settings');
    return $this->db->get()->row();
  }

  public function isDuplicate($email)
  {
    $this->db->get_where('users', array('email' => $email), 1);
    return $this->db->affected_rows() > 0 ? TRUE : FALSE;
  }
}