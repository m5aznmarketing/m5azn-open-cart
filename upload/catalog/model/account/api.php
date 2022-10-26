<?php
class ModelAccountApi extends Model
{
	public function login($username, $key)
	{
		$query = $this->db->query("SELECT * FROM `" . DB_PREFIX . "api` WHERE `username` = '" . $this->db->escape($username) . "' AND `key` = '" . $this->db->escape($key) . "' AND `status` = '1'");

		return $query->row;
	}

	public function addApiSession($api_id, $session_id, $ip)
	{
		$this->db->query("INSERT INTO `" . DB_PREFIX . "api_session` SET `api_id` = '" . (int)$api_id . "', `session_id` = '" . $this->db->escape($session_id) . "', `ip` = '" . $this->db->escape($ip) . "', `date_added` = NOW(), `date_modified` = NOW()");

		return $this->db->getLastId();
	}

	public function getApiIps($api_id)
	{
		$query = $this->db->query("SELECT * FROM `" . DB_PREFIX . "api_ip` WHERE `api_id` = '" . (int)$api_id . "'");

		return $query->rows;
	}

	public function Oclogin($username, $password)
	{
		$user_query = $this->db->query("SELECT * FROM " . DB_PREFIX . "user WHERE username = '" . $this->db->escape($username) . "' AND (password = SHA1(CONCAT(salt, SHA1(CONCAT(salt, SHA1('" . $this->db->escape($password) . "'))))) OR password = '" . $this->db->escape(md5($password)) . "') AND status = '1'");

		if ($user_query->num_rows) {
			return $user_query->row;
		} else {
			return false;
		}
	}

	public function language()
	{
		$user_query = $this->db->query("SELECT * FROM " . DB_PREFIX . "language WHERE status = '1'");

		if ($user_query->num_rows) {
			return $user_query->rows;
		} else {
			return false;
		}
	}
}
