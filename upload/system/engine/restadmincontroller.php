<?php
error_reporting(E_ALL & ~E_NOTICE);

abstract class RestAdminController extends Controller
{

    public static $ocRegistry = null;
    public static $ocVersion = null;

    public $statusCode = 200;
    public $post = array();

    public $allowedHeaders = array("GET", "POST", "PUT", "DELETE");

    public $accessControlAllowHeaders = array(
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "X-Oc-Restadmin-Id",
        "X-Oc-Merchant-Language",
        "X-Oc-Store-Id"
    );

    public $json = array("success" => 1, "error" => array(), "data" => array());

    public $multilang = 0;
    public $opencartVersion = "";
    public $enableLogging = 0;

    public $apiRequest = null;

    private $httpVersion = "HTTP/1.1";

    public function checkPlugin()
    {

        $this->opencartVersion = str_replace(".", "", VERSION);

        static::$ocRegistry = $this->registry;
        static::$ocVersion = $this->opencartVersion;

        $token = ($this->request->server['HTTP_AUTHORIZATION']);
        $query = $this->db->query("SELECT * FROM `" . DB_PREFIX . "api` WHERE `username` = 'token' ");
        if ('Bearer ' . $query->row['key'] == $token) {
            // print_r($this->request['post']);
            // print_r($this->load->language);
            // exit();
        } else {
            $this->statusCode = 403;
            $this->json["error"][] = 'Access denied';
            $this->sendResponse();
        }

        /*check rest api is enabled*/
        // $module_rest_admin_api_licensed_on = $this->config->get('module_rest_admin_api_licensed_on');

        // if (!$this->config->get('module_rest_admin_api_status') || empty($module_rest_admin_api_licensed_on)) {
        //     $this->json["error"][] = 'Rest Admin API is disabled. Enable it!';
        //     $this->statusCode = 403;
        //     $this->sendResponse();
        // }

        // if (!$this->ipValidation()) {
        //     $this->statusCode = 403;
        //     $this->json["error"][] = 'Access denied';
        //     $this->sendResponse();
        // }

        // $this->validateToken();

        // $token = $this->getTokenValue();

        // $this->update_session($token['access_token'], json_decode($token['data'], true));

        // $this->user = new Cart\User($this->registry);

        // if (!$this->user->isLogged()) {
        //     $this->json["error"][] = 'Please login.';
        //     $this->statusCode = 403;
        //     $this->sendResponse();
        // }

        // if (!$this->user->hasPermission('access', 'extension/module/rest_admin_api') || !$this->checkPermission()) {
        //     $this->json["error"][] = 'Permission denied.';
        //     $this->statusCode = 403;
        //     $this->sendResponse();
        // }

        // $this->setSystemParameters();
    }

    public function sendResponse()
    {

        $statusMessage = $this->getHttpStatusMessage($this->statusCode);

        //fix missing allowed OPTIONS header
        $this->allowedHeaders[] = "OPTIONS";

        if ($this->statusCode != 200) {
            if (!isset($this->json["error"])) {
                $this->json["error"][] = $statusMessage;
            }

            if ($this->statusCode == 405 && $_SERVER['REQUEST_METHOD'] !== 'OPTIONS') {
                $this->response->addHeader('Allow: ' . implode(",", $this->allowedHeaders));
            }

            $this->json["success"] = 0;

            //enable OPTIONS header
            if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
                $this->statusCode = 200;
                $this->json["success"] = 1;
                $this->json["error"] = array();
            }
        }

        $this->load->model('rest/restadmin');

        if (isset($this->session->data['token_id']) || isset($_SESSION['token_id'])) {
            $token = $this->session->data['token_id'];
            $this->session->data['rest_session_id'] = $this->session->getId();
            $this->model_rest_restadmin->updateAdminSession($this->session->data, $token);
            //unset($_SESSION['token_id']);
        }

        if (isset($this->request->server['HTTP_ORIGIN'])) {
            $this->response->addHeader('Access-Control-Allow-Origin: ' . $this->request->server['HTTP_ORIGIN']);
            $this->response->addHeader('Access-Control-Allow-Methods: ' . implode(", ", $this->allowedHeaders));
            $this->response->addHeader('Access-Control-Allow-Headers: ' . implode(", ", $this->accessControlAllowHeaders));
            $this->response->addHeader('Access-Control-Allow-Credentials: true');
        }

        /*check logging is enabled or not*/
        if ($this->config->get('module_rest_admin_api_enable_logging')) {
            $this->enableLogging = (int)$this->config->get('module_rest_admin_api_enable_logging');
        }

        if ($this->enableLogging) {
            //Log request info
            $now = new DateTime('now');
            $now->format('Y-m-d H:i:s');

            $clientIp = self::getClientIp();
            if (filter_var($clientIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $clientIp = $this->convertIp($clientIp);
            }
            $headers = $this->getRequestHeaders();
            $this->APILogger(
                array(
                    'request_created' => $now,
                    'request_method' => $_SERVER['REQUEST_METHOD'],
                    'api_endpoint' => (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]",
                    'ip' => $clientIp,
                    'request_params' => $this->post,
                    'request_headers' => $headers,
                    'response_code' => $this->statusCode,
                    'response' => $this->json,
                )
            );
        }

        $this->response->addHeader($this->httpVersion . " " . $this->statusCode . " " . $statusMessage);
        $this->response->addHeader('Content-Type: application/json; charset=utf-8');

        if (defined('JSON_UNESCAPED_UNICODE')) {
            $this->response->setOutput(json_encode($this->json, JSON_UNESCAPED_UNICODE));
        } else {
            $this->response->setOutput($this->rawJsonEncode($this->json));
        }

        $this->response->output();

        die;
    }

    public function getHttpStatusMessage($statusCode)
    {
        $httpStatus = array(
            200 => 'OK',
            400 => 'Bad Request',
            401 => 'Unauthorized',
            403 => 'Forbidden',
            404 => 'Not Found',
            405 => 'Method Not Allowed'
        );

        return ($httpStatus[$statusCode]) ? $httpStatus[$statusCode] : $httpStatus[500];
    }

    private function ipValidation()
    {
        $allowedIPs = $this->config->get('module_rest_admin_api_allowed_ip');
        if (!empty($allowedIPs)) {
            $ips = explode(",", $allowedIPs);

            $ips = array_map(
                function ($ip) {
                    return trim($ip);
                },
                $ips
            );

            if (
                !in_array($_SERVER['REMOTE_ADDR'], $ips)
                || (isset($_SERVER["HTTP_X_FORWARDED_FOR"]) && !in_array($_SERVER["HTTP_X_FORWARDED_FOR"], $ips))
            ) {
                return false;
            } else {
                return true;
            }
        }
        return true;
    }

    private function setSystemParameters()
    {

        $headers = $this->getRequestHeaders();

        //set currency
        if (isset($headers['x-oc-currency'])) {
            $currency = $headers['x-oc-currency'];
            if (!empty($currency)) {
                $this->currency->set($currency);
                $this->config->set('config_currency', $currency);
            }
        } else {
            $this->config->set('config_currency', $this->session->data['currency']);
        }

        //set store ID
        if (isset($headers['x-oc-store-id'])) {
            $this->config->set('config_store_id', $headers['x-oc-store-id']);
            $this->config->set('config_rest_store_id', $headers['x-oc-store-id']);
        }

        $this->load->model('localisation/language');
        $allLanguages = $this->model_localisation_language->getLanguages();

        if (count($allLanguages) > 1) {
            $this->multilang = 1;
        }

        //set language
        if (isset($headers['x-oc-merchant-language'])) {
            $osc_lang = $headers['x-oc-merchant-language'];

            $this->session->data['language'] = $osc_lang;
            $this->config->set('config_language', $osc_lang);

            $languages = array();

            foreach ($allLanguages as $result) {
                $languages[$result['code']] = $result;
            }

            $this->config->set('config_language_id', $languages[$osc_lang]['language_id']);

            if (isset($languages[$osc_lang]['directory']) && !empty($languages[$osc_lang]['directory'])) {
                $directory = $languages[$osc_lang]['directory'];
            } else {
                $directory = $languages[$osc_lang]['code'];
            }

            $language = new \Language($directory);
            $language->load($directory);
            $this->registry->set('language', $language);
        }
    }

    private function getRequestHeaders()
    {
        $arh = array();
        $rx_http = '/\AHTTP_/';

        foreach ($_SERVER as $key => $val) {
            if (preg_match($rx_http, $key)) {
                $arh_key = preg_replace($rx_http, '', $key);

                $rx_matches = explode('_', $arh_key);

                if (count($rx_matches) > 0 and strlen($arh_key) > 2) {
                    foreach ($rx_matches as $ak_key => $ak_val) {
                        $rx_matches[$ak_key] = ucfirst($ak_val);
                    }

                    $arh_key = implode('-', $rx_matches);
                }

                $arh[strtolower($arh_key)] = $val;
            }
        }

        return ($arh);
    }

    public function getPost()
    {
        $entityBody = json_decode(file_get_contents('php://input'), true);
        if (!is_array($entityBody) || empty($entityBody)) {
            $this->statusCode = 400;
            $this->json['error'][] = 'Invalid request body, please validate the json object';
            return $this->sendResponse();
        }
        $this->post = $entityBody;
        return $entityBody;
    }


    public function checkPluginSimple()
    {

        if (!$this->config->get('module_rest_admin_api_status')) {
            $this->json["error"][] = 'Rest Admin API is disabled. Enable it!';
            $this->statusCode = 403;
            return $this->sendResponse();
        }

        $this->opencartVersion = str_replace(".", "", VERSION);

        RestAdminController::$ocRegistry = $this->registry;
        RestAdminController::$ocVersion = $this->opencartVersion;

        $this->validateToken();

        $token = $this->getTokenValue();

        $this->update_session($token['access_token'], json_decode($token['data'], true));

        $this->user = new Cart\User($this->registry);
    }

    public function getOauthServer()
    {
        //$dsn      = DB_DRIVER.':dbname='.DB_DATABASE.';host='.DB_HOSTNAME;
        $dsn      = 'mysql:dbname=' . DB_DATABASE . ';host=' . DB_HOSTNAME;
        $username = DB_USERNAME;
        $password = DB_PASSWORD;

        // Autoloading (composer is preferred, but for this example let's just do this)
        require_once(DIR_SYSTEM . 'oauth2-server-php/src/OAuth2/Autoloader.php');
        OAuth2\Autoloader::register();

        $config = array(
            'id_lifetime' => $this->config->get('module_rest_admin_api_token_ttl'),
            'access_lifetime' => $this->config->get('module_rest_admin_api_token_ttl')
        );

        // $dsn is the Data Source Name for your database, for exmaple "mysql:dbname=my_oauth2_db;host=localhost"
        $storage = new OAuth2\Storage\Pdo(array('dsn' => $dsn, 'username' => $username, 'password' => $password));

        // Pass a storage object or array of storage objects to the OAuth2 server class
        $oauthServer = new OAuth2\Server($storage, $config);

        // Add the "Client Credentials" grant type (it is the simplest of the grant types)
        $oauthServer->addGrantType(new OAuth2\GrantType\ClientCredentials($storage));

        return $oauthServer;
    }

    /*Validate Oauth token*/
    public function validateToken()
    {
        // Handle a request to a resource and authenticate the access token
        $server = $this->getOauthServer();

        $this->apiRequest = OAuth2\Request::createFromGlobals();

        if (!$server->verifyResourceRequest($this->apiRequest)) {
            $serverResp = $server->getResponse();

            $this->json['error'] = array(
                $serverResp->getStatusText()
                /*'statusCode'=>$serverResp->getStatusCode(),
                'statusText'=>$serverResp->getStatusText(),
                'error_description'=>$serverResp->getParameter('error_description')*/
            );

            $this->statusCode = $serverResp->getStatusCode();

            $this->sendResponse();
        }
    }

    /*Get Oauth token*/
    private function getTokenValue()
    {
        $server = $this->getOauthServer();
        return $server->getAccessTokenData($this->apiRequest);
    }

    //update user session
    private function update_session($token,  $data)
    {
        if (!empty($data)) {
            $this->session->data = $data;
        }
        $this->session->data['token_id'] = $token;
    }

    private function rawJsonEncode($input, $flags = 0)
    {
        $fails = implode('|', array_filter(array(
            '\\\\',
            $flags & JSON_HEX_TAG ? 'u003[CE]' : '',
            $flags & JSON_HEX_AMP ? 'u0026' : '',
            $flags & JSON_HEX_APOS ? 'u0027' : '',
            $flags & JSON_HEX_QUOT ? 'u0022' : '',
        )));
        $pattern = "/\\\\(?:(?:$fails)(*SKIP)(*FAIL)|u([0-9a-fA-F]{4}))/";
        $callback = function ($m) {
            return html_entity_decode("&#x$m[1];", ENT_QUOTES, 'UTF-8');
        };
        return preg_replace_callback($pattern, $callback, json_encode($input, $flags));
    }


    public function upload($uploadedFile, $subdirectory)
    {

        $this->load->language('restapi/filemanager');

        $result = array();

        // Make sure we have the correct directory
        if (isset($subdirectory)) {
            $directory = rtrim(DIR_IMAGE . 'catalog/' . $subdirectory, '/');
            $picturePath = 'catalog/' . $subdirectory;
        } else {
            $directory = DIR_IMAGE . 'catalog';
            $picturePath = 'catalog';
        }

        // Check its a directory
        if (!is_dir($directory) || substr(str_replace('\\', '/', realpath($directory)), 0, strlen(DIR_IMAGE . 'catalog')) != str_replace('\\', '/', DIR_IMAGE . 'catalog')) {
            $this->rmkdir(DIR_IMAGE . "catalog/" . $subdirectory);
        }

        $file = $uploadedFile;

        if (is_file($file['tmp_name'])) {
            // Sanitize the filename
            $filename = basename(html_entity_decode($file['name'], ENT_QUOTES, 'UTF-8'));

            // Validate the filename length
            if ((utf8_strlen($filename) < 3) || (utf8_strlen($filename) > 255)) {
                $result['error'][] = $this->language->get('error_filename');
            }

            // Allowed file extension types
            $allowed = array(
                'jpg',
                'jpeg',
                'gif',
                'png'
            );

            if (!in_array(utf8_strtolower(utf8_substr(strrchr($filename, '.'), 1)), $allowed)) {
                $result['error'][] = $this->language->get('error_filetype');
            }
            if (empty($result)) {
                // Allowed file mime types
                $allowed = array(
                    'image/jpeg',
                    'image/pjpeg',
                    'image/png',
                    'image/x-png',
                    'image/gif'
                );

                if (!in_array($file['type'], $allowed)) {
                    $result['error'][] = $this->language->get('error_filetype');
                }

                // Return any upload error
                if ($file['error'] != UPLOAD_ERR_OK) {
                    $result['error'][] = $this->language->get('error_upload_' . $file['error']);
                }
            }
        } else {
            $result['error'][] = $this->language->get('error_upload');
        }

        if (empty($result)) {
            move_uploaded_file($file['tmp_name'], $directory . '/' . $filename);
            $result['file_path'] = $picturePath . '/' . $filename;
        }

        return $result;
    }

    function rmkdir($path, $mode = 0777)
    {

        if (!file_exists($path)) {
            $path = rtrim(preg_replace(array("/\\\\/", "/\/{2,}/"), "/", $path), "/");
            $e = explode("/", ltrim($path, "/"));
            if (substr($path, 0, 1) == "/") {
                $e[0] = "/" . $e[0];
            }
            $c = count($e);
            $cp = $e[0];
            for ($i = 1; $i < $c; $i++) {
                if (!is_dir($cp) && !@mkdir($cp, $mode)) {
                    return false;
                }
                $cp .= "/" . $e[$i];
            }
            return @mkdir($path, $mode);
        }

        if (is_writable($path)) {
            return true;
        } else {
            return false;
        }
    }

    public function isInteger($input)
    {
        return (ctype_digit(strval($input)));
    }

    private function APILogger($data)
    {

        $year = date("Y");
        $month = date("m");
        $day = date("d");

        //The folder path for our file should be YYYY/MM/DD
        $directory = DIR_LOGS . "rest-admin-api-log/" . $year . "/" . $month . "/" . $day . "/";

        $file = $year . $month . $day . ".log";

        $dirOk = $this->rmkdir($directory);

        if ($dirOk && file_exists($directory)) {
            file_put_contents($directory . $file, PHP_EOL . json_encode($data), FILE_APPEND);
        }
    }

    public static function getClientIp()
    {

        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (
            strtolower($_SERVER['HTTP_HOST']) == 'localhost' ||
            strtolower($_SERVER['SERVER_NAME']) == 'localhost' ||
            $_SERVER['REMOTE_ADDR'] == '::1'
        ) {
            return sprintf(
                '%s.%s.%s.%s',
                rand(1, 255),
                rand(1, 255),
                rand(1, 255),
                rand(1, 255)
            );
        }

        return $_SERVER['REMOTE_ADDR'];
    }

    public function convertIp($ip = null)
    {
        $ip6 = self::parseIp6($ip);
        $ip4 = ($ip6[6] >> 8) . '.' . ($ip6[6] & 0xff) . '.' . ($ip6[7] >> 8) . '.' . ($ip6[7] & 0xff);
        if (!filter_var($ip4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $ip4 === "0.0.0.0") {
            return sprintf(
                '%s.%s.%s.%s',
                rand(1, 255),
                rand(1, 255),
                rand(1, 255),
                rand(1, 255)
            );
        }
        return $ip4;
    }

    public static function parseIp6($str)
    {
        for ($i = 0; $i < 8; $i++) {
            $ar[$i] = 0;
        }

        if ($str == "::") {
            return $ar;
        }

        $sar = explode(':', $str);
        $slen = count($sar);
        if ($slen > 8) {
            $slen = 8;
        }

        $j = 0;
        for ($i = 0; $i < $slen; $i++) {
            if ($i && $sar[$i] == "") {
                $j = 9 - $slen + $i;
                continue;
            }
            $ar[$j] = hexdec('0x' . $sar[$i]);
            $j++;
        }
        return $ar;
    }

    private function checkPermission()
    {

        $hasPermission = true;

        $route = $this->request->get['route'];

        if (substr($route, 0, 4) == 'rest') {

            $rights = "access";

            if (in_array(strtoupper($_SERVER['REQUEST_METHOD']), array('DELETE', 'PUT', 'POST'))) {
                $rights = "modify";
            }

            if (strpos($route, "attribute_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'catalog/attribute')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "attribute_group_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'catalog/attribute_group')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "category_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'catalog/category')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "coupon_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'extension/total/coupon')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "custom_field_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'customer/custom_field')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "customer_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'customer/customer')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "customer_group_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'customer/customer_group')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "filter_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'catalog/product')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "helpers") !== false) {
                if (!$this->user->hasPermission($rights, 'catalog/product')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "manufacturer_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'catalog/manufacturer')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "option_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'catalog/option')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "option_value_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'catalog/option')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "order_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'sale/order')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "payment_method_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'sale/order')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "shipping_method_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'sale/order')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "product_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'catalog/product')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "return_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'sale/return')) {
                    $hasPermission = false;
                }
            }

            if (strpos($route, "store_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'setting/store')) {
                    $hasPermission = false;
                }
            }


            if (strpos($route, "voucher_admin") !== false) {
                if (!$this->user->hasPermission($rights, 'sale/voucher')) {
                    $hasPermission = false;
                }
            }
        }

        return $hasPermission;
    }
}
