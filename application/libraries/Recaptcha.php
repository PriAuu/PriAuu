<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Recaptcha
{

  private $dataSitekey = "";
  private $lang = "en";
  public $secret = '';

  public function render()
  {
    $return = '<div class="g-recaptcha" data-sitekey="' . $this->dataSitekey . '"></div>
            <script src="https://www.google.com/recaptcha/api.js?hl=' . $this->lang . '" async defer></script>';
    return $return;
  }
}
