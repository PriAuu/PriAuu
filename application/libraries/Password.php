<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

class Password
{

  const PBKDF2_HASH_ALGORITHM = 'sha256';
  const PBKDF2_ITERATIONS = 1000;
  const PBKDF2_SALT_BYTE_SIZE = 24;
  const PBKDF2_HASH_BYTE_SIZE = 24;

  const HASH_SECTIONS = 4;
  const HASH_ALGORITHM_INDEX = 0;
  const HASH_ITERATION_INDEX = 1;
  const HASH_SALT_INDEX = 2;
  const HASH_PBKDF2_INDEX = 3;

  function create_hash($password)
  {
    $salt = base64_encode(password_hash(self::PBKDF2_SALT_BYTE_SIZE, MCRYPT_DEV_URANDOM));
    return self::PBKDF2_HASH_ALGORITHM . ":" . self::PBKDF2_ITERATIONS . ":" .  $salt . ":" .
      base64_encode($this->pbkdf2(
        self::PBKDF2_HASH_ALGORITHM,
        $password,
        $salt,
        self::PBKDF2_ITERATIONS,
        self::PBKDF2_HASH_BYTE_SIZE,
        true
      ));
  }

  function pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false)
  {
    $algorithm = strtolower($algorithm);
    if (!in_array($algorithm, hash_algos(), true))
      die('PBKDF2 ERROR: Invalid hash algorithm.');
    if ($count <= 0 || $key_length <= 0)
      die('PBKDF2 ERROR: Invalid parameters.');

    $hash_length = strlen(hash($algorithm, "", true));
    $block_count = ceil($key_length / $hash_length);

    $output = "";
    for ($i = 1; $i <= $block_count; $i++) {
      $last = $salt . pack("N", $i);
      $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
      for ($j = 1; $j < $count; $j++) {
        $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
      }
      $output .= $xorsum;
    }

    if ($raw_output)
      return substr($output, 0, $key_length);
    else
      return bin2hex(substr($output, 0, $key_length));
  }

  function validate_password($password, $correct_hash)
  {
    $params = explode(":", $correct_hash);
    if (count($params) < self::HASH_SECTIONS)
      return false;
    $pbkdf2 = base64_decode($params[self::HASH_PBKDF2_INDEX]);
    return $this->slow_equals(
      $pbkdf2,
      $this->pbkdf2(
        $params[self::HASH_ALGORITHM_INDEX],
        $password,
        $params[self::HASH_SALT_INDEX],
        (int)$params[self::HASH_ITERATION_INDEX],
        strlen($pbkdf2),
        true
      )
    );
  }

  function slow_equals($a, $b)
  {
    $diff = strlen($a) ^ strlen($b);
    for ($i = 0; $i < strlen($a) && $i < strlen($b); $i++) {
      $diff |= ord($a[$i]) ^ ord($b[$i]);
    }
    return $diff === 0;
  }
}
