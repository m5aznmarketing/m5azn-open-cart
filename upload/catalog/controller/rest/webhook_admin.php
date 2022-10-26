<?php

require_once(DIR_SYSTEM . 'engine/restadmincontroller.php');

class ControllerRestWebhookAdmin extends RestAdminController
{

    public function newWebhook()
    {
        $this->checkPlugin();
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $this->load->language('restapi/webhook');

            $post = $this->getPost();

            if (!isset($post['key'])) {
                $this->json['error'][] = 'Key required';
                $this->statusCode = 401;
            } else {
                $query = $this->db->query("SELECT * FROM `" . DB_PREFIX . "api` WHERE `username` = 'm5azn_new_order' ");
                if ($query->num_rows > 0) {
                    $result = $query->row;
                    $this->json['data'] = $result;
                } else {
                    require_once 'admin/model/user/api.php';

                    $option = new ModelUserApi($this->registry);
                    $data['username'] = 'm5azn_new_order';
                    $data['key'] = $post['key'];
                    $data['status'] = 1;
                    $result['api_id'] = $option->addApi($data);
                    $result['key'] =  $data['key'];
                    $result['username'] =  $data['username'];
                    $this->json['data'] = $result;
                }
                if (!$this->json) {
                    $this->json['error'][] = 'Unsuccessful';
                    $this->statusCode = 500;
                }
            }
        } else {
            $this->statusCode = 405;
            $this->allowedHeaders = array("POST");
        }

        return $this->sendResponse();
    }

    public function deleteWebhook()
    {
        $this->checkPlugin();
        if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
            $this->load->language('restapi/webhook');
            $post = $this->getPost();

            $query = $this->db->query("DELETE FROM `" . DB_PREFIX . "api` WHERE `key` = '" . $post['key'] . "'");
            if ($query->num_rows == 0) {
                $this->json['data'] = true;
            } else {
                $this->json['data'] = false;
            }
        } else {
            $this->statusCode = 405;
            $this->allowedHeaders = array("");
        }

        return $this->sendResponse();
    }
}
