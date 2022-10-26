<?php
/**
 * customer_admin.php
 *
 * Customer management
 *
 * @author          Opencart-api.com
 * @copyright       2017
 * @license         License.txt
 * @version         2.0
 * @link            https://opencart-api.com/product/opencart-rest-admin-api/
 * @documentations  https://opencart-api.com/opencart-rest-api-documentations/
 */
require_once(DIR_SYSTEM . 'engine/restadmincontroller.php');

class ControllerRestCustomerAdmin extends RestAdminController
{

    static $defaultFields = array(
        "firstname",
        "lastname",
        "email",
        "telephone",
        "newsletter",
        "status",
        "approved",
        "safe",
        "customer_group_id",
        "custom_field",

    );

    static $defaultFieldValues = array(
        "newsletter" => 0,
        "status" => 1,
        "approved" => 1,
        "safe" => 0,
        "customer_group_id" => 1,
    );

    static $customerAddressFields = array(
        "firstname",
        "lastname",
        "company",
        "address_1",
        "address_2",
        "city",
        "country_id",
        "postcode",
        "country",
        "zone_id"
    );

    static $customerAffiliateFields = array(
        "company",
        "website",
        "tracking",
        "commission",
        "tax",
        "payment",
        "cheque",
        "paypal",
        "bank_name",
        "bank_branch_number",
        "bank_swift_code",
        "bank_account_name",
        "bank_account_number",
        "custom_field",
        "status"
    );

    public function customers()
    {

        $this->checkPlugin();

        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            //get customer details
            if (isset($this->request->get['id']) && $this->isInteger($this->request->get['id'])) {
                $this->getCustomer($this->request->get['id']);
            } else {
                //get customers list
                $this->listCustomers($this->request);
            }
        } else if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $post = $this->getPost();
            $this->addCustomer($post);
        } else if ($_SERVER['REQUEST_METHOD'] === 'PUT') {
            //update customer
            $post = $this->getPost();

            if (isset($this->request->get['id']) && $this->isInteger($this->request->get['id'])) {
                $this->editCustomer($this->request->get['id'], $post);
            } else {
                $this->statusCode = 400;
            }

        } else if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {

            //delete customer by ID
            if (isset($this->request->get['id']) && $this->isInteger($this->request->get['id'])) {
                $this->load->model('rest/restadmin');
                $customer = $this->model_rest_restadmin->getCustomer($this->request->get['id']);

                if($customer) {
                    $post["customers"] = array($this->request->get['id']);
                    $this->deleteCustomers($post);
                } else {
                    $this->json['error'][] = "Customer not found";
                    $this->statusCode = 404;
                }

            } else {

                $post = $this->getPost();

                if (isset($post["customers"])) {
                    $this->deleteCustomers($post);
                } else {
                    $this->statusCode = 400;
                }
            }
        }

        return $this->sendResponse();
    }

    private function getCustomer($id)
    {

        $this->load->model('account/customer');

        if ($this->isInteger($id)) {
            $customer = $this->model_account_customer->getCustomer($id);

            if (!empty($customer['customer_id'])) {
                $this->json['data'] = $this->getCustomerInfo($customer);
            } else {
                $this->json['error'][] = "Customer not found";
                $this->statusCode = 404;
            }
        } else {
            $this->statusCode = 400;
        }
    }

    private function getCustomerInfo($customer)
    {

        $this->load->model('account/custom_field');
        $this->load->model('rest/restadmin');

        $custom_fields = $this->model_account_custom_field->getCustomFields($customer['customer_group_id']);

        $account_custom_field = json_decode($customer['custom_field'], true);

        $addresses = $this->model_rest_restadmin->getAddresses($customer['customer_id']);

        $affiliate_info = $this->model_rest_restadmin->getAffiliate($customer['customer_id']);

        if(!empty($affiliate_info) ) {
            if(!empty($affiliate_info["custom_field"]) ) {
                $affiliate_info["custom_field"] = json_decode($affiliate_info["custom_field"], true);
            } else {
                $affiliate_info = array();
            }
        } else {
            $affiliate_info = array();
        }

        return array(
            'store_id' => (int)$customer['store_id'],
            'customer_id' => (int)$customer['customer_id'],
            'customer_group_id' => (int)$customer['customer_group_id'],
            'firstname' => $customer['firstname'],
            'lastname' => $customer['lastname'],
            'telephone' => $customer['telephone'],
            'email' => $customer['email'],
            'newsletter' => (int)$customer['newsletter'],
            'status' => (int)$customer['status'],
            'approved' => isset($customer['approved']) ? (int)$customer['approved'] : "",
            'safe' => (int)$customer['safe'],
            'date_added' => date($this->language->get('date_format_short'), strtotime($customer['date_added'])),
            'addresses' => array_values($addresses),
            'affiliate' => $affiliate_info,
            'account_custom_field' => empty($account_custom_field) ? array() : $account_custom_field,
            'custom_fields' => $custom_fields,
            'reward_points' => $this->model_rest_restadmin->getTotalPoints($customer['customer_id']),
            'transaction_total' => $this->currency->format($this->model_rest_restadmin->getTransactionTotal($customer['customer_id']), $this->config->get('config_currency'))
        );

    }

    private function listCustomers($request)
    {

        $this->load->language('restapi/customer');
        $this->load->model('rest/restadmin');
        $this->load->model('account/custom_field');

        $parameters = array(
            "limit" => $this->config->get('config_limit_admin'),
            "start" => 1,
        );

        /*check limit parameter*/
        if (isset($request->get['limit']) && $this->isInteger($request->get['limit'])) {
            $parameters["limit"] = $request->get['limit'];
        }

        /*check page parameter*/
        $page = 1;
        if (isset($request->get['page']) && $this->isInteger($request->get['page'])) {
            $parameters["start"] = $request->get['page'];
            $page = $request->get['page'];
        }

        $parameters["start"] = ($parameters["start"] - 1) * $parameters["limit"];

        if (isset($request->get['filter_date_added_from'])) {
            $date_added_from = date('Y-m-d H:i:s', strtotime($request->get['filter_date_added_from']));
            if ($this->validateDate($date_added_from)) {
                $filter_date_added_from = $date_added_from;
            }
        } else {
            $filter_date_added_from = null;
        }

        if (isset($request->get['filter_date_added_on'])) {
            $date_added_on = date('Y-m-d', strtotime($request->get['filter_date_added_on']));
            if ($this->validateDate($date_added_on, 'Y-m-d')) {
                $filter_date_added_on = $date_added_on;
            }
        } else {
            $filter_date_added_on = null;
        }


        if (isset($request->get['filter_date_added_to'])) {
            $date_added_to = date('Y-m-d H:i:s', strtotime($request->get['filter_date_added_to']));
            if ($this->validateDate($date_added_to)) {
                $filter_date_added_to = $date_added_to;
            }
        } else {
            $filter_date_added_to = null;
        }

        if (isset($request->get['filter_in_group']) && $this->isInteger($request->get['filter_in_group'])) {
            $filter_in_group = $request->get['filter_in_group'];
        } else {
            $filter_in_group = null;
        }

        $customers = array();

        $parameters['filter_customer_group_id'] = $filter_in_group;
        $parameters['filter_date_added_on'] = $filter_date_added_on;
        $parameters['filter_date_added_from'] = $filter_date_added_from;
        $parameters['filter_date_added_to'] = $filter_date_added_to;

        $results = $this->model_rest_restadmin->getCustomers($parameters);

        foreach ($results as $result) {

            $addresses = $this->model_rest_restadmin->getAddresses($result['customer_id']);
            $custom_fields = $this->model_account_custom_field->getCustomFields($result['customer_group_id']);

            $account_custom_field = json_decode($result['custom_field'], true);

            $affiliate_info = $this->model_rest_restadmin->getAffiliate($result['customer_id']);

            if(!empty($affiliate_info) ) {
                if(!empty($affiliate_info["custom_field"]) ) {
                    $affiliate_info["custom_field"] = json_decode($affiliate_info["custom_field"], true);
                } else {
                    $affiliate_info = array();
                }
            } else {
                $affiliate_info = array();
            }

            $val = array(
                'customer_id' => (int)$result['customer_id'],
                'customer_group_id' => (int)$result['customer_group_id'],
                'firstname' => $result['firstname'],
                'lastname' => $result['lastname'],
                'name' => $result['name'],
                'email' => $result['email'],
                'newsletter' => (int)$result['newsletter'],
                'status' => (int)$result['status'],
                'approved' => isset($result['approved']) ? (int)$result['approved'] : "",
                'safe' => (int)$result['safe'],
                'ip' => $result['ip'],
                'telephone' => $result['telephone'],
                'reward_points' => $this->model_rest_restadmin->getTotalPoints($result['customer_id']),
                'account_custom_field' => empty($account_custom_field) ? array() : $account_custom_field,
                'custom_fields' => $custom_fields,
                'affiliate' => $affiliate_info,
                'addresses' => array_values($addresses),
                'date_added' => date($this->language->get('date_format_short'), strtotime($result['date_added'])),
            );

            $ret['transaction_total'] = $this->currency->format($this->model_rest_restadmin->getTransactionTotal($result['customer_id']), $this->config->get('config_currency'));

            $customers['customers'][] = $val;
        }

        $this->json['data'] = !empty($customers) ? $customers['customers'] : array();
        $total = $this->model_rest_restadmin->getCustomers($parameters, true);

        $this->response->addHeader('X-Total-Count: ' . (int)$total);
        $this->response->addHeader('X-Pagination-Limit: ' . (int)$parameters["limit"]);
        $this->response->addHeader('X-Pagination-Page: ' . (int)($page));
    }

    private function validateDate($date, $format = 'Y-m-d H:i:s')
    {
        $d = DateTime::createFromFormat($format, $date);
        return $d && $d->format($format) == $date;
    }

    public function addCustomer($post)
    {

        $this->load->model('rest/restadmin');
        $this->load->language('restapi/customer');

        $this->loadData($post);

        $error = $this->validateForm($post);

        if (empty($error)) {
            $customerId = $this->model_rest_restadmin->addCustomer($post);
            $this->json["data"]["id"] = $customerId;
        } else {
            $this->json['error'] = $error;
            $this->statusCode = 400;
        }

    }

    private function loadData(&$post, $customer = null)
    {

        foreach (self::$defaultFields as $field) {
            if (!isset($post[$field])) {
                if (!empty($customer) && isset($customer[$field])) {
                    if($field == "custom_field"){
                        $post[$field] = json_decode($customer[$field], true);
                    } else {
                        $post[$field] = $customer[$field];
                    }
                } else {
                    $post[$field] = (isset(self::$defaultFieldValues[$field]) && empty($customer) ) ? self::$defaultFieldValues[$field] : "";
                }
            }
        }

        foreach (self::$customerAddressFields as $field) {
            if (isset($post["address"])) {
                foreach ($post["address"] as &$address) {
                    if (!isset($address[$field])) {
                        $address[$field] = "";
                    }
                }
            }
        }

        $affiliate_info = array();

        if (isset($post['affiliate']) && !empty($customer) && isset($customer['customer_id'])) {
            $affiliate_info = $this->model_rest_restadmin->getAffiliate($customer['customer_id']);
        }

        foreach (self::$customerAffiliateFields as $field) {
            if (isset($post["affiliate"])) {
                if (!isset($post["affiliate"][$field])) {
                    if (!empty($affiliate_info) && isset($affiliate_info[$field])) {
                        if($field == "custom_field"){
                            $post["affiliate"][$field] = json_decode($affiliate_info[$field], true);
                        } else {
                            $post["affiliate"][$field] = $affiliate_info[$field];
                        }
                    } else {
                        if ($field == 'status') {
                            $post["affiliate"][$field] = 0;
                        } elseif ($field == 'commission') {
                            $post["affiliate"][$field] = $this->config->get('config_affiliate_commission');
                        } elseif ($field == 'custom_field') {
                            $post["affiliate"][$field] = array();
                        } else {
                            $post["affiliate"][$field] = "";
                        }
                    }
                }
            }
        }
    }

    private function validateForm($post, $customer_id = null)
    {

        $this->load->model('account/customer');
        $this->load->language('restapi/customer');

        $error = array();

        if ((!isset($post['firstname']) && empty($customer_id)) || (utf8_strlen($post['firstname']) < 1) || (utf8_strlen(trim($post['firstname'])) > 32)) {
            $error[] = $this->language->get('error_firstname');
        }

        if ((!isset($post['lastname'])  && empty($customer_id))  || (utf8_strlen($post['lastname']) < 1) || (utf8_strlen(trim($post['lastname'])) > 32)) {
            $error[] = $this->language->get('error_lastname');
        }

        if ((!isset($post['email']) && empty($customer_id))  || (utf8_strlen($post['email']) > 96) || !preg_match('/^[^\@]+@.*.[a-z]{2,15}$/i', $post['email'])) {
            $error[] = $this->language->get('error_email');
        }

        if(isset($post['email']) && !empty($post['email'])) {
            $customer_info = $this->model_account_customer->getCustomerByEmail($post['email']);

            if (empty($customer_id)) {
                if ($customer_info) {
                    $error[] = $this->language->get('error_exists');
                }
            } else {
                if ($customer_info && ($customer_id != $customer_info['customer_id'])) {
                    $error[] = $this->language->get('error_exists');
                }
            }
        }

        if ((!isset($post['telephone']) && empty($customer_id))  || (utf8_strlen($post['telephone']) < 3) || (utf8_strlen($post['telephone']) > 32)) {
            $error[] = $this->language->get('error_telephone');
        }

        if(isset($post['customer_group_id'])){
            // Custom field validation
            $custom_fields = $this->model_rest_restadmin->getCustomFields(array('filter_customer_group_id' => $post['customer_group_id']));

            foreach ($custom_fields as $custom_field) {
                if (($custom_field['location'] == 'account') && $custom_field['required'] && empty($post['custom_field'][$custom_field['custom_field_id']])) {
                    $error[] = sprintf($this->language->get('error_custom_field'), $custom_field['name']);
                } elseif (($custom_field['location'] == 'account') && ($custom_field['type'] == 'text') && !empty($custom_field['validation']) && !filter_var($post['custom_field'][$custom_field['custom_field_id']], FILTER_VALIDATE_REGEXP, array('options' => array('regexp' => $custom_field['validation'])))) {
                    $error[] = sprintf($this->language->get('error_custom_field'), $custom_field['name']);
                }
            }
        }


        if (isset($post['password']) || (!isset($customer_id))) {
            if (!isset($post['password']) || (utf8_strlen($post['password']) < 4) || (utf8_strlen($post['password']) > 20)) {
                $error[] = $this->language->get('error_password');
            }

            if (!isset($post['confirm']) || ($post['password'] != $post['confirm'])) {
                $error[] = $this->language->get('error_confirm');
            }
        }

        if (isset($post['address'])) {

            foreach ($post['address'] as $key => $value) {

                if (!isset($value['firstname']) || (utf8_strlen($value['firstname']) < 1) || (utf8_strlen($value['firstname']) > 32)) {
                    $error[] = $this->language->get('error_firstname');
                }

                if (!isset($value['lastname']) || (utf8_strlen($value['lastname']) < 1) || (utf8_strlen($value['lastname']) > 32)) {
                    $error[] = $this->language->get('error_lastname');
                }

                if (!isset($value['address_1']) || (utf8_strlen($value['address_1']) < 3) || (utf8_strlen($value['address_1']) > 128)) {
                    $error[] = $this->language->get('error_address_1');
                }

                if (!isset($value['city']) || (utf8_strlen($value['city']) < 2) || (utf8_strlen($value['city']) > 128)) {
                    $error[] = $this->language->get('error_city');
                }

                $this->load->model('localisation/country');

                if (isset($value['country_id']) && !empty($value['country_id'])) {

                    $country_info = $this->model_localisation_country->getCountry($value['country_id']);

                    if ($country_info && $country_info['postcode_required'] && (!isset($value['postcode']) || (utf8_strlen($value['postcode']) < 2 || utf8_strlen($value['postcode']) > 10))) {
                        $error[] = $this->language->get('error_postcode');
                    }

                } else {
                    $error[] = $this->language->get('error_country');
                }

                if (!isset($value['zone_id']) || empty($value['zone_id'])) {
                    $error[] = $this->language->get('error_zone');
                }


                foreach ($custom_fields as $custom_field) {
                    if (($custom_field['location'] == 'address') && $custom_field['required'] && empty($value['custom_field'][$custom_field['custom_field_id']])) {
                        $error[] = sprintf($this->language->get('error_custom_field'), $custom_field['name']);
                    } elseif (($custom_field['location'] == 'address') && ($custom_field['type'] == 'text') && !empty($custom_field['validation']) && !filter_var($value['custom_field'][$custom_field['custom_field_id']], FILTER_VALIDATE_REGEXP, array('options' => array('regexp' => $custom_field['validation'])))) {
                        $error[] = sprintf($this->language->get('error_custom_field'), $custom_field['name']);
                    }
                }
            }
        }

        if (isset($post['affiliate'])) {

            $postedAffiliate = $post['affiliate'];

            if ($postedAffiliate['payment'] == 'cheque') {
                if (empty($postedAffiliate['cheque'])) {
                    $error[] = $this->language->get('error_cheque');
                }
            } elseif ($postedAffiliate['payment'] == 'paypal') {
                if ((utf8_strlen($postedAffiliate['paypal']) > 96) || !filter_var($postedAffiliate['paypal'], FILTER_VALIDATE_EMAIL)) {
                    $error[] = $this->language->get('error_paypal');
                }
            } elseif ($postedAffiliate['payment'] == 'bank') {
                if (empty($postedAffiliate['bank_account_name'])) {
                    $error[] = $this->language->get('error_bank_account_name');
                }

                if (empty($postedAffiliate['bank_account_number'])) {
                    $error[] = $this->language->get('error_bank_account_number');
                }
            }

            if (!$postedAffiliate['tracking']) {
                $error[] = $this->language->get('error_tracking');
            }

            $affiliate_info = $this->model_rest_restadmin->getAffliateByTracking($postedAffiliate['tracking']);

            if (empty($customer_id)) {
                if ($affiliate_info) {
                    $error[] = $this->language->get('error_tracking_exists');
                }
            } else {
                if ($affiliate_info && ($customer_id != $affiliate_info['customer_id'])) {
                    $error[] = $this->language->get('error_tracking_exists');
                }
            }

            foreach ($custom_fields as $custom_field) {
                if (($custom_field['location'] == 'affiliate') && $custom_field['required'] && empty($postedAffiliate['custom_field'][$custom_field['custom_field_id']])) {
                    $error[] = sprintf($this->language->get('error_custom_field'), $custom_field['name']);
                } elseif (($custom_field['location'] == 'affiliate') && ($custom_field['type'] == 'text') && !empty($custom_field['validation']) && !filter_var($postedAffiliate['custom_field'][$custom_field['custom_field_id']], FILTER_VALIDATE_REGEXP, array('options' => array('regexp' => $custom_field['validation'])))) {
                    $error[] = sprintf($this->language->get('error_custom_field'), $custom_field['name']);
                }
            }
        }

        return $error;
    }

    public function editCustomer($id, $post)
    {

        $this->load->language('restapi/customer');
        $this->load->model('rest/restadmin');
        $this->load->model('account/custom_field');

        $customer = $this->model_rest_restadmin->getCustomer($id);

        if($customer) {

            $this->loadData($post, $customer);
            $error = $this->validateForm($post, $id);

            if (!empty($post) && empty($error)) {

                $custom_fields = $this->model_account_custom_field->getCustomFields($post['customer_group_id']);
                $accountCustomfield = array();

                //we have to remove all affiliate specific custom fields
                foreach ($custom_fields as $custom_field) {
                    if (($custom_field['location'] == 'account')) {
                        if(isset($post['custom_field'][$custom_field['custom_field_id']])) {
                            $accountCustomfield[$custom_field['custom_field_id']] = $post['custom_field'][$custom_field['custom_field_id']];
                        }
                    }
                }

                $post['custom_field'] = $accountCustomfield;

                $this->model_rest_restadmin->editCustomer($id, $post);
            } else {
                $this->json['error'] = $error;
                $this->statusCode = 400;
            }
        } else {
            $this->json['error'][] = "Customer not found";
            $this->statusCode = 404;
        }

    }

    public function deleteCustomers($post)
    {

        $this->load->model('rest/restadmin');

        if (isset($post['customers']) && !empty($post['customers'])) {
            foreach ($post['customers'] as $customers) {
                $this->model_rest_restadmin->deleteCustomer($customers);
            }
        } else {
            $this->statusCode = 400;
        }

    }

    public function reward()
    {

        $this->checkPlugin();


        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $post = $this->getPost();

            $error = $this->validateReward($post);

            if (isset($this->request->get['id']) && $this->isInteger($this->request->get['id'])
                && empty($error)
            ) {
                $id = $this->request->get['id'];
                $this->load->model('account/customer');
                $customer = $this->model_account_customer->getCustomer($id);
                if (!empty($customer['customer_id'])) {
                    $this->load->model('rest/restadmin');
                    $this->model_rest_restadmin->addReward($id, $post);
                } else {
                    $this->json['error'][] = "Customer not found";
                    $this->statusCode = 404;
                }
            } else {
                $this->json['error'] = $error;
                $this->statusCode = 400;
            }
        } else {
            $this->statusCode = 405;
            $this->allowedHeaders = array("POST");
        }

        return $this->sendResponse();
    }

    protected function validateReward($post)
    {
        $error = array();

        if(!isset($post['description']) || empty($post["description"])) {
            $error[] = "Reward description is required";
        }

        if(!isset($post['points']) || empty($post["points"])) {
            $error[] = "Reward points is required";
        }

        return $error;
    }

    protected function validateTransaction($post)
    {
        $error = array();

        if(!isset($post['description']) || empty($post["description"])) {
            $error[] = "Transaction description is required";
        }

        if(!isset($post['amount']) || empty($post["amount"])) {
            $error[] = "Transaction amount is required";
        }

        return $error;
    }

    public function transactions()
    {

        $this->checkPlugin();

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {

            $post = $this->getPost();

            $error = $this->validateTransaction($post);

            if (isset($this->request->get['id']) && $this->isInteger($this->request->get['id'])
                && empty($error)) {

                $id = $this->request->get['id'];

                $this->load->model('account/customer');
                $customer = $this->model_account_customer->getCustomer($id);

                if (!empty($customer['customer_id'])) {

                    $this->load->model('rest/restadmin');

                    $description = isset($post['description']) ? $post['description'] : "";
                    $amount = isset($post['amount']) ? $post['amount'] : 0;

                    $this->load->model('rest/restadmin');
                    $this->model_rest_restadmin->addTransaction($id, $description, $amount);


                } else {
                    $this->json['error'][] = "Customer not found";
                    $this->statusCode = 404;
                }
            } else {
                $this->json['error'] = $error;
                $this->statusCode = 400;
            }
        } else {
            $this->statusCode = 405;
            $this->allowedHeaders = array("POST");
        }

        return $this->sendResponse();
    }


    public function getcustomerbyemail()
    {

        $this->checkPlugin();

        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            if (isset($this->request->get['email']) && !empty($this->request->get['email'])) {
                $this->load->model('rest/restadmin');

                $id = $this->model_rest_restadmin->getCustomersByEmail($this->request->get['email']);
                if ($id) {
                    $this->getCustomer($id);
                } else {
                    $this->json['error'][] = "Customer not found";
                    $this->statusCode = 404;
                }
            } else {
                $this->json['error'][] = "Email is required.";
                $this->statusCode = 400;
            }
        } else {
            $this->statusCode = 405;
            $this->allowedHeaders = array("GET");
        }

        return $this->sendResponse();
    }
}