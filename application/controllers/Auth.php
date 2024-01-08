<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Auth extends CI_Controller
{
  
    public function register()
    {
        if (empty($this->session->userdata['email'])) {
            redirect(site_url() . 'auth/login');
        } else {
            $data = $this->session->userdata;
            $this->load->model('register_model');

            $this->form_validation->set_rules('firstname', 'Firstname Name', 'required');
            $this->form_validation->set_rules('lastname', 'Last Name', 'required');
            $this->form_validation->set_rules('email', 'Email', 'required|valid_email');
            $this->form_validation->set_rules('password', 'Password', 'required|min_length[5]');
            $this->form_validation->set_rules('passconf', 'Password Confirmation', 'required|matches[password]');

            $data['title'] = "Add User";
            if ($this->form_validation->run() == FALSE) {
                $this->load->view('auth/register', $data);
            } else {
                if ($this->register_model->isDuplicate($this->input->post('email'))) {
                    $this->session->set_flashdata('flash_message', 'User email already exists');
                    redirect(site_url() . 'register');
                } else {

                    $this->load->library('password');
                    $this->load->model('user_model');

                    $post = $this->input->post(NULL, TRUE);
                    $cleanPost = $this->security->xss_clean($post);
                    $hashed = $this->password->create_hash($cleanPost['password']);

                    $cleanPost['email'] = $this->input->post('email');
                    $cleanPost['role'] = '4';
                    $cleanPost['status'] = '1';
                    $cleanPost['firstname'] = $this->input->post('firstname');
                    $cleanPost['lastname'] = $this->input->post('lastname');
                    $cleanPost['banned_users'] = 'unban';
                    $cleanPost['password'] = $hashed;
                    unset($cleanPost['passconf']);

                    //insert to database
                    if (!$this->user_model->addUser($cleanPost)) {
                        $this->session->set_flashdata('flash_message', 'There was a problem add new user');
                        redirect(site_url() . 'auth/register');
                    } else {
                        $this->session->set_flashdata('success_message', 'New user has been added.');
                        redirect(site_url() . 'auth/register');
                    }
                    $this->session->sess_destroy();
                    redirect(site_url() . 'auth/completed');
                };
            }
        }
    }

    public function register_completed()
    {
        $this->load->view('auth/register_completed');
    }

  public function __construct()
  {
    parent::__construct();

    $this->load->model('user_model');
    $this->load->library('password');
    $this->load->library('recaptcha');
    $this->load->library('tank_auth');
    $this->status = $this->config->item('status');
    $this->banned_users = $this->config->item('banned_users');
  }

  public function login()
  {

    if ($this->tank_auth->is_logged_in()) {                                    // logged in
      $this->executeRedirection();
    } elseif ($this->tank_auth->is_logged_in(false)) {                        // logged in, not activated
      redirect('/auth/send_again/');
    } else {
      $data['login_by_username'] = ($this->config->item('login_by_username', 'tank_auth') and
        $this->config->item('use_username', 'tank_auth'));
      $data['login_by_email'] = $this->config->item('login_by_email', 'tank_auth');

      //เป็น library ที่ชื่อ form_validation
      $this->form_validation->set_rules('email', 'Email', 'required');
      $this->form_validation->set_rules('password', 'Password', 'required');

      // Get login for counting attempts to login
      if (
        $this->config->item('login_count_attempts', 'tank_auth') and
        ($login = $this->input->post('login'))
      ) {
        $login = $this->security->xss_clean($login);
      } else {
        $login = '';
      }

      $result = $this->user_model->getAllSettings();
      $data['recaptcha'] = $result->recaptcha;

      if ($this->form_validation->run() == FALSE) {
        $this->load->view('auth/login', $data);
      } else {
        $post = $this->input->post();
        $clean = $this->security->xss_clean($post);
        $userInfo = $this->user_model->checkLogin($clean);
        if ($data['recaptcha'] == 'yes') {
          $recaptchaResponse = $this->input->post('g-recaptcha-response');
          $userIp = $_SERVER['REMOTE_ADDR'];
          $key = $this->recaptcha->secret;
          $url = "https://www.google.com/recaptcha/api/siteverify?secret=" . $key . "&response=" . $recaptchaResponse . "&remoteip=" . $userIp;
          $response = $this->curl->simple_get($url);
          $status = json_decode($response, true);

          if (!$userInfo) {
            $this->session->set_flashdata('flash_message', 'Wrong password or email.');
            redirect(site_url() . 'auth/login');
          } elseif ($userInfo->banned_users == "ban") {
            $this->session->set_flashdata('danger_message', 'You’re temporarily banned from our website!');
            redirect(site_url() . 'auth/login');
          } else if (!$status['success']) {

            $this->session->set_flashdata('flash_message', 'Error...! Google Recaptcha UnSuccessful!');
            redirect(site_url() . 'auth/login');
            exit;
          } elseif ($status['success'] && $userInfo && $userInfo->banned_users == "unban") {
            foreach ($userInfo as $key => $val) {
              $this->session->set_userdata($key, $val);
            }
            redirect(site_url() . 'auth/login');
          } else {
            $this->session->set_flashdata('flash_message', 'Something Error!');
            redirect(site_url() . 'auth/login');
            exit;
          }
        } else {
          if (!$userInfo) {
            $this->session->set_flashdata('flash_message', 'Wrong password or email.');
            redirect(site_url() . 'auth/login');
          } elseif ($userInfo->banned_users == "ban") {
            $this->session->set_flashdata('danger_message', 'You’re temporarily banned from our website!');
            redirect(site_url() . 'auth/login');
          } elseif ($userInfo && $userInfo->banned_users == "unban") {
            foreach ($userInfo as $key => $val) {
              $this->session->set_userdata($key, $val);
            }
            redirect(site_url() . 'auth/login');
          } else {
            $this->session->set_flashdata('flash_message', 'Something Error!');
            redirect(site_url() . 'auth/login');
            exit;
          }
        }
      }
    }
  }
}
