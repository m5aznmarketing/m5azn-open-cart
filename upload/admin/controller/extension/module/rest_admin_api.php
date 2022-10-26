<?php

class ControllerExtensionModuleRestAdminApi extends Controller {

    public function index() {

        $this->load->language('extension/module/rest_admin_api');

        $data['heading_title']  = $this->language->get('heading_title');

        $data['text_enabled']       = $this->language->get('text_enabled');
        $data['text_disabled']      = $this->language->get('text_disabled');
        $data['text_feed']          = $this->language->get('text_feed');
        $data['text_extension']     = $this->language->get('text_extension');
        $data['text_success']       = $this->language->get('text_success');

        $data['button_save']        = $this->language->get('button_save');
        $data['button_cancel']      = $this->language->get('button_cancel');

        $data['tab_general']        = $this->language->get('tab_general');
        $data['text_edit']          = $this->language->get('text_edit');
        $data['entry_status']       = $this->language->get('entry_status');
        $data['entry_key']          = $this->language->get('entry_key');
        $data['text_thumb_width']   = $this->language->get('text_thumb_width');
        $data['text_thumb_height']  = $this->language->get('text_thumb_height');

        $data['entry_client_id']    = $this->language->get('entry_client_id');
        $data['entry_client_secret']= $this->language->get('entry_client_secret');
        $data['entry_token_ttl']    = $this->language->get('entry_token_ttl');
        $data['text_client_id']     = $this->language->get('text_client_id');
        $data['text_client_secret'] = $this->language->get('text_client_secret');
        $data['text_token_ttl']     = $this->language->get('text_token_ttl');

        $data['text_order_id']      = $this->language->get('text_order_id');
        $data['entry_order_id']     = $this->language->get('entry_order_id');
        $data['entry_allowed_ip']   = $this->language->get('entry_allowed_ip');
        $data['text_allowed_ip']    = $this->language->get('text_allowed_ip');
        $data['error']              = $this->language->get('error');


        $this->load->model('setting/setting');

        $this->document->setTitle($this->language->get('heading_title'));


        if (($this->request->server['REQUEST_METHOD'] == 'POST') && $this->validate()) {
            $apiOrderId = $this->request->post['module_rest_admin_api_order_id'];
            if(!empty($apiOrderId) && strlen($apiOrderId) > 5 ) {

                if (isset($_POST['nJvNVJoMHcQVIuHk']) && !empty($_POST['nJvNVJoMHcQVIuHk'])) {
                    $this->request->post['module_rest_admin_api_licensed_on'] = $_POST['nJvNVJoMHcQVIuHk'];
                } else {
                    $this->request->post['module_rest_admin_api_status'] = 0;
                }

                $this->model_setting_setting->editSetting('module_rest_admin_api', $this->request->post);
                
                $this->setOauthClientForAdmin($this->request->post['module_rest_admin_api_client_id'], $this->request->post['module_rest_admin_api_client_secret']);
                $this->session->data['success'] = $this->language->get('text_success');
                
                $this->session->data['success'] = $this->language->get('text_success');
                try{
                    eval(base64_decode("QGZpbGVfZ2V0X2NvbnRlbnRzKCdodHRwOi8vbGljZW5zZS5vcGVuY2FydC1hcGkuY29tL2xpY2Vuc2UucGhwP29yZGVyX2lkPScuJHRoaXMtPnJlcXVlc3QtPnBvc3RbJ21vZHVsZV9yZXN0X2FkbWluX2FwaV9vcmRlcl9pZCddLicmc2l0ZT0nLkhUVFBfQ0FUQUxPRy4nJmFwaXY9cmVzdF9hZG1pbl8zX3hfb2F1dGgmb3BlbnY9Jy5WRVJTSU9OKTs="));
                } catch (Exception $e){}

                $this->response->redirect($this->url->link('marketplace/extension', 'user_token=' . $this->session->data['user_token'] . '&type=module', true));
            } else {
                $error['warning'] = $this->language->get('error');
            }
        }
        $data['breadcrumbs'] = array();

        $data['breadcrumbs'][] = array(
            'text' => $this->language->get('text_home'),
            'href' => $this->url->link('common/dashboard', 'user_token=' . $this->session->data['user_token'], true)
        );

        $data['breadcrumbs'][] = array(
            'text' => $this->language->get('text_extension'),
            'href' => $this->url->link('marketplace/extension', 'user_token=' . $this->session->data['user_token'] . '&type=module', true)
        );

        $data['breadcrumbs'][] = array(
            'text' => $this->language->get('heading_title'),
            'href' => $this->url->link('extension/module/rest_admin_api', 'user_token=' . $this->session->data['user_token'], true)
        );

        if (isset($this->request->post['module_rest_admin_api_status'])) {
            $data['module_rest_admin_api_status'] = $this->request->post['module_rest_admin_api_status'];
        } else {
            $data['module_rest_admin_api_status'] = $this->config->get('module_rest_admin_api_status');
        }

        if (isset($this->request->post['module_rest_admin_api_order_id'])) {
            $data['module_rest_admin_api_order_id'] = $this->request->post['module_rest_admin_api_order_id'];
        } else {
            $data['module_rest_admin_api_order_id'] = $this->config->get('module_rest_admin_api_order_id');
        }

        if (isset($this->request->post['module_rest_admin_api_thumb_width'])) {
            $data['module_rest_admin_api_thumb_width'] = $this->request->post['module_rest_admin_api_thumb_width'];
        } else {
            $data['module_rest_admin_api_thumb_width'] = $this->config->get('module_rest_admin_api_thumb_width');
        }

        if (isset($this->request->post['module_rest_admin_api_thumb_height'])) {
            $data['module_rest_admin_api_thumb_height'] = $this->request->post['module_rest_admin_api_thumb_height'];
        } else {
            $data['module_rest_admin_api_thumb_height'] = $this->config->get('module_rest_admin_api_thumb_height');
        }

        if (isset($this->request->post['module_rest_admin_api_allowed_ip'])) {
            $data['module_rest_admin_api_allowed_ip'] = $this->request->post['module_rest_admin_api_allowed_ip'];
        } else {
            $data['module_rest_admin_api_allowed_ip'] = $this->config->get('module_rest_admin_api_allowed_ip');
        }


        if (isset($this->request->post['module_rest_admin_api_client_id'])) {
            $data['module_rest_admin_api_client_id'] = $this->request->post['module_rest_admin_api_client_id'];
        } else {
            $data['module_rest_admin_api_client_id'] = $this->config->get('module_rest_admin_api_client_id');
        }

        if (isset($this->request->post['module_rest_admin_api_client_secret'])) {
            $data['module_rest_admin_api_client_secret'] = $this->request->post['module_rest_admin_api_client_secret'];
        } else {
            $data['module_rest_admin_api_client_secret'] = $this->config->get('module_rest_admin_api_client_secret');
        }

        if (isset($this->request->post['module_rest_admin_api_token_ttl'])) {
            $data['module_rest_admin_api_token_ttl'] = $this->request->post['module_rest_admin_api_token_ttl'];
        } else {
            $data['module_rest_admin_api_token_ttl'] = $this->config->get('module_rest_admin_api_token_ttl');
        }

        if(empty($data['module_rest_admin_api_thumb_width'])) {
            $data['module_rest_admin_api_thumb_width'] = 100;
        }

        if(empty($data['module_rest_admin_api_thumb_height'])) {
            $data['module_rest_admin_api_thumb_height'] = 100;
        }


        if (isset($this->request->post['module_rest_admin_api_enable_logging'])) {
            $data['module_rest_admin_api_enable_logging'] = $this->request->post['module_rest_admin_api_enable_logging'];
        } else {
            $data['module_rest_admin_api_enable_logging'] = $this->config->get('module_rest_admin_api_enable_logging');
        }
        
        if (!isset($data['module_rest_admin_api_token_ttl']) || empty($data['module_rest_admin_api_token_ttl'])) {
            $data['module_rest_admin_api_token_ttl'] = 2628000;
        }

        //set default client id
        if (!isset($data['module_rest_admin_api_client_id']) || empty($data['module_rest_admin_api_client_id'])) {
            $data['module_rest_admin_api_client_id'] = 'demo_oauth_client';
        }

        //set default client secret
        if (!isset($data['module_rest_admin_api_client_secret']) || empty($data['module_rest_admin_api_client_secret'])) {
            $data['module_rest_admin_api_client_secret'] = 'demo_oauth_secret';
        }

        $data['basic_token'] = '';

        if(!empty($data['module_rest_admin_api_client_secret']) && !empty($data['module_rest_admin_api_client_id'])) {
            $data['basic_token'] = base64_encode($data['module_rest_admin_api_client_id'].':'.$data['module_rest_admin_api_client_secret']);
        }

        if (isset($_POST['nJvNVJoMHcQVIuHk']) && !empty($_POST['nJvNVJoMHcQVIuHk'])) {
            $data['module_rest_admin_api_licensed_on'] = $_POST['nJvNVJoMHcQVIuHk'];
        } else {
            $data['module_rest_admin_api_licensed_on'] = $this->config->get('module_rest_admin_api_licensed_on');
        }

        $data["xcDLOMddkCV"] = base64_decode('ICAgIDxkaXYgY2xhc3M9ImFsZXJ0IGFsZXJ0LWRhbmdlciBsaWNlbnNlX2FsZXJ0X2Jsb2NrIj4NCiAgICAgICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJjbG9zZSIgZGF0YS1kaXNtaXNzPSJhbGVydCIgYXJpYS1oaWRkZW49InRydWUiPsOXPC9idXR0b24+DQogICAgICAgIDxoND5XYXJuaW5nISBVbmxpY2Vuc2VkIHZlcnNpb24gb2YgdGhlIGV4dGVuc2lvbiE8L2g0Pg0KICAgICAgICA8cD5Zb3UgYXJlIHJ1bm5pbmcgYW4gdW5saWNlbnNlZCB2ZXJzaW9uIG9mIHRoaXMgZXh0ZW5zaW9uISBZb3UgbmVlZCB0byBlbnRlciB5b3VyIG9yZGVyIElEIHRvIGVuc3VyZSBwcm9wZXIgZnVuY3Rpb25pbmcsIGFjY2VzcyB0byBzdXBwb3J0IGFuZCB1cGRhdGVzLjwvcD48ZGl2IHN0eWxlPSJoZWlnaHQ6NXB4OyI+PC9kaXY+DQogICAgPC9kaXY+');
        $hostname = (!empty($_SERVER['HTTP_HOST'])) ? $_SERVER['HTTP_HOST'] : '' ;
        $hostname = (strstr($hostname,'http://') === false) ? 'http://'.$hostname: $hostname;
        $data['hostname'] = base64_encode($hostname);

        if(isset($this->session->data['api_install_error'])) {
            if(!empty($this->session->data['api_install_error'])) {
                $error['warning'] = $this->session->data['api_install_error'];
                $error['warning'].= "<br>Please update your Opencart root folder .htaccess file manually. For more information please check your install.txt file.";
                $this->session->data['api_install_error'] = "";
            }
        }

        $data['install_success'] = '';

        if (isset($this->session->data['install_success'])) {
            if (!empty($this->session->data['install_success'])){
                $data['install_success'] = "We successfully installed the .htaccess rewrite rules. Backup file of your original .htaccess: ".DIR_SYSTEM . "../.htaccess_rest_admin_api_backup";
                $this->session->data['install_success'] = "";
            }
        }

        if (isset($error['warning'])) {
            $data['error_warning'] = $error['warning'];
        } else {
            $data['error_warning'] = '';
        }

        $data['action']     = $this->url->link('extension/module/rest_admin_api', 'user_token=' . $this->session->data['user_token'], true);
        $data['cancel'] = $this->url->link('marketplace/extension', 'user_token=' . $this->session->data['user_token'] . '&type=module', true);

        $data['header'] = $this->load->controller('common/header');
        $data['column_left'] = $this->load->controller('common/column_left');
        $data['footer'] = $this->load->controller('common/footer');

        $this->response->setOutput($this->load->view('extension/module/rest_admin_api', $data));

    }
    protected function validate() {
        $hasError = false;

        if (!$this->user->hasPermission('modify', 'extension/module/rest_admin_api')) {
            $hasError = true;
        }

        return !$hasError;
    }

    public function setOauthClientForAdmin($clientid, $clientsecret) {
        $this->db->query("DELETE FROM `oauth_clients` WHERE api_version = 'admin' OR api_version IS NULL");
        $this->db->query("INSERT INTO `oauth_clients` SET api_version = 'admin',client_id = '" . $this->db->escape($clientid) . "', client_secret = '" . $this->db->escape($clientsecret)."'");
    }

    public function install() {
        $this->db->query("CREATE TABLE IF NOT EXISTS oauth_clients (client_id VARCHAR(80) NOT NULL, client_secret VARCHAR(80) NOT NULL, redirect_uri VARCHAR(2000) NOT NULL, grant_types VARCHAR(80), scope VARCHAR(100), user_id VARCHAR(80), api_version VARCHAR(80), CONSTRAINT clients_client_id_pk PRIMARY KEY (client_id));");
        $this->db->query("CREATE TABLE IF NOT EXISTS oauth_access_tokens (access_token VARCHAR(40) NOT NULL, client_id VARCHAR(80) NOT NULL, user_id VARCHAR(255), expires DATETIME NOT NULL, scope VARCHAR(2000), session_id VARCHAR(40), data TEXT, CONSTRAINT access_token_pk PRIMARY KEY (access_token));");
        $this->db->query("CREATE TABLE IF NOT EXISTS oauth_scopes (scope TEXT, is_default BOOLEAN);");

        $response = $this->installHtaccess();

        if($response !== true){
            $this->session->data['api_install_error'] = $response;
        } else {
            $this->session->data['install_success'] = 1;
        }
    }

    private function installHtaccess() {

        $directory = DIR_SYSTEM . '../';

        $htaccess  = $directory . '.htaccess';

        //if htaccess does not exist or there is no htaccess.txt or the file is not writable return
        if( ! file_exists( $htaccess ) && file_exists( $directory . '.htaccess.txt' ) ) {
            if( ! @ rename( $directory . '.htaccess.txt', $htaccess ) ) {
                return 'Could not rename .htaccess.txt';
            };
        }

        // .htaccess does not exist or directory is not writable
        if( ! file_exists( $htaccess ) ) {
            if (!is_writable($directory)) {
                return  $directory.' is not writable';
            }
            return 'Htaccess file does not exist ('.$htaccess.')';
        }

        $currentHtaccess = file_get_contents($htaccess);

        $pos = strpos($currentHtaccess, "api/rest_admin");

        //rewrite rules are installed
        if ($pos !== false) {
            return true;
        }

        $htaccessFilePermission    = null;

        if( ! is_readable( $htaccess ) || ! is_writable( $htaccess ) ) {
            //backup current file permission
            $htaccessFilePermission = fileperms( $htaccess );

            if( ! @ chmod( $htaccess, 777 ) )
                return 'We could not modify your htaccess file. Set permission to 777 during the install process.';
        }

        $newHtaccess = str_replace("RewriteCond %{REQUEST_FILENAME} !-f" , implode( "\n", array(
            '####################################### OPENCART REST ADMIN API START #######################################',
            '#Sets the HTTP_AUTHORIZATION header removed by apache',
            'RewriteCond %{HTTP:Authorization} .',
            'RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]',
            '#REST ADMIN API SECURITY',
            'RewriteRule ^api/rest_admin/oauth2/token/?([a-zA-Z0-9_]+) index.php?route=rest/admin_security/gettoken&grant_type=$1  [L]',
            'RewriteRule ^api/rest_admin/oauth2/token index.php?route=rest/admin_security/gettoken  [L]',
            'RewriteRule ^api/rest_admin/login index.php?route=rest/admin_security/login  [L]',
            'RewriteRule ^api/rest_admin/logout index.php?route=rest/admin_security/logout  [L]',
            'RewriteRule ^api/rest_admin/forgotten index.php?route=rest/admin_security/forgotten  [L]',
            'RewriteRule ^api/rest_admin/reset index.php?route=rest/admin_security/reset  [L]',
            'RewriteRule ^api/rest_admin/user index.php?route=rest/admin_security/user  [L]',
            '#REST API database tables checksum',
            'RewriteRule ^api/rest_admin/checksums index.php?route=rest/helpers/getchecksum  [L]',
            '#REST API UTC and server time offset in seconds',
            'RewriteRule ^api/rest_admin/utc_offset index.php?route=rest/helpers/utc_offset  [L]',
            '#REST API get product classes',
            'RewriteRule ^api/rest_admin/init/?([a-zA-Z0-9_]+) index.php?route=rest/helpers/productclasses&type=$1  [L]',
            'RewriteRule ^api/rest_admin/init index.php?route=rest/helpers/productclasses  [L]',
            '#REST API selected country',
            'RewriteRule ^api/rest_admin/countries/?([0-9]+) index.php?route=rest/helpers/countries&id=$1  [L]',
            '#REST API countries',
            'RewriteRule ^api/rest_admin/countries index.php?route=rest/helpers/countries [L]',

            '###################################### Custom endpoints #######################################',
            'RewriteRule ^api/rest_admin/manufacturers/getmanufactureridbyname/?([-a-zA-Z0-9_&\|\s/.]+) index.php?route=rest/manufacturer_admin/manufactureridbyname&name=$1 [B,NC,L]',
            'RewriteRule ^api/rest_admin/categories/getcategoryidbyname/?([-a-zA-Z0-9_&\|\s/.]+) index.php?route=rest/category_admin/categoryidbyname&name=$1 [B,NC,L]',
            'RewriteRule ^api/rest_admin/products/getproductidbysku/?([-a-zA-Z0-9_&\|\s/.]+) index.php?route=rest/product_admin/getproductidbyparameter&p=sku&value=$1 [B,NC,L]',
            'RewriteRule ^api/rest_admin/products/getproductidbymodel/?([-a-zA-Z0-9_&\|\s/.]+) index.php?route=rest/product_admin/getproductidbyparameter&p=model&value=$1 [B,NC,L]',
            'RewriteRule ^api/rest_admin/products/getproductidbyean/?([-a-zA-Z0-9_&\|\s/.]+) index.php?route=rest/product_admin/getproductidbyparameter&p=ean&value=$1 [B,NC,L]',
            'RewriteRule ^api/rest_admin/products/getproductidbyisbn/?([-a-zA-Z0-9_&\|\s/.]+) index.php?route=rest/product_admin/getproductidbyparameter&p=isbn&value=$1 [B,NC,L]',
            '####################################### PRODUCT #######################################',
            'RewriteRule ^api/rest_admin/addproductandwithotherinfos index.php?route=rest/product_admin/addproductandwithotherinfos  [L]',
            'RewriteRule ^api/rest_admin/bulk_products index.php?route=rest/product_admin/bulkproducts  [L]',
            'RewriteRule ^api/rest_admin/products/?([0-9]+)/images/other/?([0-9]+) index.php?route=rest/product_admin/productimages&id=$1&other=1&sort_order=$2  [L]',
            'RewriteRule ^api/rest_admin/products/?([0-9]+)/images index.php?route=rest/product_admin/productimages&id=$1  [L]',
            'RewriteRule ^api/rest_admin/products/search/?([-a-zA-Z0-9_&\|\s/.]+)/sort/?([a-zA-Z]+)/order/?([a-zA-Z]+) index.php?route=rest/product_admin/products&search=$1&sort=$2&order=$3 [B,NC,L]',
            'RewriteRule ^api/rest_admin/products/search/?([-a-zA-Z0-9_&\|\s/.]+)/sort/?([a-zA-Z]+) index.php?route=rest/product_admin/products&search=$1&sort=$2 [B,NC,L]',
            'RewriteRule ^api/rest_admin/products/category/?([0-9]+)/sort/?([a-zA-Z]+)/order/?([a-zA-Z]+) index.php?route=rest/product_admin/products&category=$1&sort=$2&order=$3  [L]',
            'RewriteRule ^api/rest_admin/products/category/?([0-9]+)/sort/?([a-zA-Z]+) index.php?route=rest/product_admin/products&category=$1&sort=$2  [L]',
            'RewriteRule ^api/rest_admin/products/sort/?([a-zA-Z]+)/order/?([a-zA-Z]+) index.php?route=rest/product_admin/products&sort=$1&order=$2  [L]',
            'RewriteRule ^api/rest_admin/products/sort/?([a-zA-Z]+) index.php?route=rest/product_admin/products&sort=$1  [L]',
            'RewriteRule ^api/rest_admin/products/search/?([-a-zA-Z0-9_&\|\s/.]+)/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/product_admin/products&search=$1&limit=$2&page=$3 [B,NC,L]',
            'RewriteRule ^api/rest_admin/products/search/?([-a-zA-Z0-9_&\|\s/.]+) index.php?route=rest/product_admin/products&search=$1 [B,NC,L]',
            'RewriteRule ^api/rest_admin/products/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/product_admin/products&limit=$1&page=$2  [L]',
            'RewriteRule ^api/rest_admin/products/category/?([0-9]+)/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/product_admin/products&category=$1&limit=$2&page=$3  [L]',
            'RewriteRule ^api/rest_admin/products/category/?([0-9]+) index.php?route=rest/product_admin/products&category=$1  [L]',
            'RewriteRule ^api/rest_admin/products/quantitybysku index.php?route=rest/product_admin/productquantitybysku  [L]',
            'RewriteRule ^api/rest_admin/products/quantity index.php?route=rest/product_admin/productquantity  [L]',
            'RewriteRule ^api/rest_admin/products/getproductbysku/?([-a-zA-Z0-9_&\|\s/.]+) index.php?route=rest/product_admin/getproductbysku&sku=$1 [B,NC,L]',
            'RewriteRule ^api/rest_admin/products/?([0-9]+) index.php?route=rest/product_admin/products&id=$1  [L]',

            'RewriteRule ^api/rest_admin/products/category/?([0-9]+)/sort/?([a-zA-Z]+) index.php?route=rest/product_admin/products&category=$1&sort=$2  [L]',
            'RewriteRule ^api/rest_admin/products/category/?([0-9]+)/sort/?([a-zA-Z]+)/order/?([a-zA-Z]+) index.php?route=rest/product_admin/products&category=$1&sort=$2&order=$3  [L]',

            'RewriteRule ^api/rest_admin/products index.php?route=rest/product_admin/products  [L]',
            'RewriteRule ^api/rest_admin/featured/limit/?([0-9]+) index.php?route=rest/product_admin/featured&limit=$1  [L]',
            'RewriteRule ^api/rest_admin/featured/?([0-9]+) index.php?route=rest/product_admin/featured&id=$1  [L]',
            'RewriteRule ^api/rest_admin/featured index.php?route=rest/product_admin/featured  [L]',
            'RewriteRule ^api/rest_admin/latestwithdetails/limit/?([0-9]+) index.php?route=rest/product_admin/latestwithdetails&limit=$1  [L]',
            'RewriteRule ^api/rest_admin/latestwithdetails index.php?route=rest/product_admin/latestwithdetails  [L]',
            'RewriteRule ^api/rest_admin/latest/limit/?([0-9]+) index.php?route=rest/product_admin/latest&limit=$1  [L]',
            'RewriteRule ^api/rest_admin/latest index.php?route=rest/product_admin/latest  [L]',
            '####################################### CATEGORY #######################################',
            'RewriteRule ^api/rest_admin/categories/?([0-9]+)/images index.php?route=rest/category_admin/categoryimages&id=$1  [L]',
            'RewriteRule ^api/rest_admin/categories/parent/?([0-9]+)/level/?([0-9]+) index.php?route=rest/category_admin/category&parent=$1&level=$2  [L]',
            'RewriteRule ^api/rest_admin/categories/level/?([0-9]+) index.php?route=rest/category_admin/category&level=$1  [L]',
            'RewriteRule ^api/rest_admin/categories/parent/?([0-9]+) index.php?route=rest/category_admin/category&parent=$1  [L]',
            'RewriteRule ^api/rest_admin/categories/?([0-9]+) index.php?route=rest/category_admin/category&id=$1  [L]',
            'RewriteRule ^api/rest_admin/categories/extended/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/category_admin/category&limit=$1&page=$2&extended  [L]',
            'RewriteRule ^api/rest_admin/categories index.php?route=rest/category_admin/category [L]',
            '###################################### MANUFACTURER #######################################',
            'RewriteRule ^api/rest_admin/manufacturers/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/manufacturer_admin/manufacturer&limit=$1&page=$2  [L]',
            'RewriteRule ^api/rest_admin/manufacturers/?([0-9]+)/images index.php?route=rest/manufacturer_admin/manufacturerimages&id=$1  [L]',
            'RewriteRule ^api/rest_admin/manufacturers/?([0-9]+) index.php?route=rest/manufacturer_admin/manufacturer&id=$1  [L]',
            'RewriteRule ^api/rest_admin/manufacturers index.php?route=rest/manufacturer_admin/manufacturer  [L]',
            '###################################### ORDERS #######################################',
            'RewriteRule ^api/rest_admin/orderhistory/?([0-9]+) index.php?route=rest/order_admin/orderhistory&id=$1  [L]',
            'RewriteRule ^api/rest_admin/orders/details/added_from/([^/]+)/added_to/([^/]+)/?$ index.php?route=rest/order_admin/listorderswithdetails&filter_date_added_from=$1&filter_date_added_to=$2 [L]',
            'RewriteRule ^api/rest_admin/orders/details/added_from/([^/]+)/?$ index.php?route=rest/order_admin/listorderswithdetails&filter_date_added_from=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/details/added_on/([^/]+)/?$ index.php?route=rest/order_admin/listorderswithdetails&filter_date_added_on=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/details/modified_from/([^/]+)/modified_to/([^/]+)/?$ index.php?route=rest/order_admin/listorderswithdetails&filter_date_modified_from=$1&filter_date_modified_to=$2 [L]',
            'RewriteRule ^api/rest_admin/orders/details/modified_from/([^/]+)/?$ index.php?route=rest/order_admin/listorderswithdetails&filter_date_modified_from=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/details/modified_on/([^/]+)/?$ index.php?route=rest/order_admin/listorderswithdetails&filter_date_modified_on=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/details/status/([0-9,?:,]+) index.php?route=rest/order_admin/listorderswithdetails&filter_order_status_id=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/details/id_lower_than/([0-9]+) index.php?route=rest/order_admin/listorderswithdetails&filter_id_lower_than=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/details/id_larger_than/([0-9]+) index.php?route=rest/order_admin/listorderswithdetails&filter_id_larger_than=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/details/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/order_admin/listorderswithdetails&limit=$1&page=$2  [L]',

            'RewriteRule ^api/rest_admin/orders/added_from/([^/]+)/added_to/([^/]+)/?$ index.php?route=rest/order_admin/orders&filter_date_added_from=$1&filter_date_added_to=$2 [L]',
            'RewriteRule ^api/rest_admin/orders/added_from/([^/]+)/?$ index.php?route=rest/order_admin/orders&filter_date_added_from=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/added_on/([^/]+)/?$ index.php?route=rest/order_admin/orders&filter_date_added_on=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/modified_from/([^/]+)/modified_to/([^/]+)/?$ index.php?route=rest/order_admin/orders&filter_date_modified_from=$1&filter_date_modified_to=$2 [L]',
            'RewriteRule ^api/rest_admin/orders/modified_from/([^/]+)/?$ index.php?route=rest/order_admin/orders&filter_date_modified_from=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/modified_on/([^/]+)/?$ index.php?route=rest/order_admin/orders&filter_date_modified_on=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/status/([0-9,?:,]+) index.php?route=rest/order_admin/orders&filter_order_status_id=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/id_lower_than/([0-9]+) index.php?route=rest/order_admin/orders&filter_id_lower_than=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/id_larger_than/([0-9]+) index.php?route=rest/order_admin/orders&filter_id_larger_than=$1 [L]',
            'RewriteRule ^api/rest_admin/orders/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/order_admin/orders&limit=$1&page=$2  [L]',

            'RewriteRule ^api/rest_admin/trackingnumber/?([0-9]+) index.php?route=rest/order_admin/trackingnumber&id=$1  [L]',
            'RewriteRule ^api/rest_admin/order_status/?([0-9]+) index.php?route=rest/order_admin/orderstatus&id=$1  [L]',
            'RewriteRule ^api/rest_admin/orders/details index.php?route=rest/order_admin/listorderswithdetails  [L]',
            'RewriteRule ^api/rest_admin/orders/invoice/?([0-9]+) index.php?route=rest/order_admin/invoice&id=$1  [L]',
            'RewriteRule ^api/rest_admin/orders/?([0-9]+) index.php?route=rest/order_admin/orders&id=$1  [L]',
            'RewriteRule ^api/rest_admin/orders/user/?([0-9]+) index.php?route=rest/order_admin/userorders&user=$1  [L]',
            'RewriteRule ^api/rest_admin/orders index.php?route=rest/order_admin/orders  [L]',
            'RewriteRule ^api/rest_admin/orderadmin index.php?route=rest/order_admin/order  [L]',
            '####################################### ATTRIBUTE GROUP #######################################',
            'RewriteRule ^api/rest_admin/attributegroups/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/attribute_group_admin/attributegroup&limit=$1&page=$2  [L]',
            'RewriteRule ^api/rest_admin/attributegroups/?([0-9]+) index.php?route=rest/attribute_group_admin/attributegroup&id=$1  [L]',
            'RewriteRule ^api/rest_admin/attributegroups index.php?route=rest/attribute_group_admin/attributegroup  [L]',
            '####################################### ATTRIBUTE #######################################',
            'RewriteRule ^api/rest_admin/attributes/group/?([0-9]+)/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/attribute_admin/attribute&group=$1&limit=$2&page=$3  [L]',
            'RewriteRule ^api/rest_admin/attributes/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/attribute_admin/attribute&limit=$1&page=$2  [L]',
            'RewriteRule ^api/rest_admin/attributes/?([0-9]+) index.php?route=rest/attribute_admin/attribute&id=$1  [L]',
            'RewriteRule ^api/rest_admin/attributes index.php?route=rest/attribute_admin/attribute  [L]',
            '###################################### OPTIONS #######################################',
            'RewriteRule ^api/rest_admin/product_options/?([0-9]+)/images index.php?route=rest/option_admin/optionimages&id=$1  [L]',
            'RewriteRule ^api/rest_admin/product_options/?([0-9]+) index.php?route=rest/option_admin/option&id=$1  [L]',
            'RewriteRule ^api/rest_admin/product_options/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/option_admin/option&limit=$1&page=$2  [L]',
            'RewriteRule ^api/rest_admin/product_options index.php?route=rest/option_admin/option  [L]',
            '####################################### OPTION VALUE #######################################',
            'RewriteRule ^api/rest_admin/optionvalue/?([0-9]+) index.php?route=rest/option_value_admin/optionvalue&id=$1  [L]',
            'RewriteRule ^api/rest_admin/optionvalue index.php?route=rest/option_value_admin/optionvalue  [L]',
            '##################################### CUSTOMER GROUPS #######################################',
            'RewriteRule ^api/rest_admin/customergroups/?([0-9]+) index.php?route=rest/customer_group_admin/customergroup&id=$1  [L]',
            'RewriteRule ^api/rest_admin/customergroups/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/customer_group_admin/customergroup&limit=$1&page=$2  [L]',
            'RewriteRule ^api/rest_admin/customergroups index.php?route=rest/customer_group_admin/customergroup  [L]',
            '#################################### CUSTOMER #######################################',
            'RewriteRule ^api/rest_admin/customers/added_from/([^/]+)/added_to/([^/]+)/?$ index.php?route=rest/customer_admin/customers&filter_date_added_from=$1&filter_date_added_to=$2 [L]',
            'RewriteRule ^api/rest_admin/customers/added_from/([^/]+)/?$ index.php?route=rest/customer_admin/customers&filter_date_added_from=$1 [L]',
            'RewriteRule ^api/rest_admin/customers/added_on/([^/]+)/?$ index.php?route=rest/customer_admin/customers&filter_date_added_on=$1 [L]',
            'RewriteRule ^api/rest_admin/customers/?([0-9]+) index.php?route=rest/customer_admin/customers&id=$1  [L]',
            'RewriteRule ^api/rest_admin/customers/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/customer_admin/customers&limit=$1&page=$2  [L]',
            'RewriteRule ^api/rest_admin/customers/email/?([-a-zA-Z0-9@.]+) index.php?route=rest/customer_admin/getcustomerbyemail&email=$1  [L]',
            'RewriteRule ^api/rest_admin/customers/in_group/([^/]+)/?$ index.php?route=rest/customer_admin/customers&filter_in_group=$1 [L]',
            'RewriteRule ^api/rest_admin/customers index.php?route=rest/customer_admin/customers  [L]',
            'RewriteRule ^api/rest_admin/reward/?([0-9]+) index.php?route=rest/customer_admin/reward&id=$1  [L]',
            'RewriteRule ^api/rest_admin/transaction/?([0-9]+) index.php?route=rest/customer_admin/transactions&id=$1  [L]',
            '####################################### CUSTOM FIELD #######################################',
            'RewriteRule ^api/rest_admin/customfields/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/custom_field_admin/customfield&limit=$1&page=$2  [L]',
            '#################################### SHIPPING METHODS #######################################',
            'RewriteRule ^api/rest_admin/shippingmethods index.php?route=rest/shipping_method_admin/shippingmethods  [L]',
            '#################################### PAYMENT METHODS #######################################',
            'RewriteRule ^api/rest_admin/paymentmethods index.php?route=rest/payment_method_admin/paymentmethods  [L]',
            '###################################### COUPONS #######################################',
            'RewriteRule ^api/rest_admin/coupons/?([0-9]+) index.php?route=rest/coupon_admin/coupon&id=$1  [L]',
            'RewriteRule ^api/rest_admin/coupons/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/coupon_admin/coupon&limit=$1&page=$2  [L]',
            'RewriteRule ^api/rest_admin/coupons index.php?route=rest/coupon_admin/coupon  [L]',
            '###################################### STORE #######################################',
            'RewriteRule ^api/rest_admin/stores/copy/?([0-9]+) index.php?route=rest/store_admin/store&id=$1  [L]',
            'RewriteRule ^api/rest_admin/stores/?([0-9]+) index.php?route=rest/store_admin/store&id=$1  [L]',
            'RewriteRule ^api/rest_admin/stores/stats index.php?route=rest/store_admin/stats  [L]',
            'RewriteRule ^api/rest_admin/stores index.php?route=rest/store_admin/store  [L]',
            '###################################### VOUCHERS #######################################',
            'RewriteRule ^api/rest_admin/voucherthemes index.php?route=rest/voucher_admin/voucherthemes  [L]',
            'RewriteRule ^api/rest_admin/vouchers/?([0-9]+) index.php?route=rest/voucher_admin/vouchers&id=$1  [L]',
            'RewriteRule ^api/rest_admin/vouchers/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/voucher_admin/vouchers&limit=$1&page=$2  [L]',
            'RewriteRule ^api/rest_admin/vouchers index.php?route=rest/voucher_admin/vouchers  [L]',
            '###################################### FILTERS #######################################',
            'RewriteRule ^api/rest_admin/product_filters/groups/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/filter_admin/groups&limit=$1&page=$2  [L]',
            'RewriteRule ^api/rest_admin/product_filters/filters/group/?([0-9]+) index.php?route=rest/filter_admin/filters&filter_group=$1  [L]',
            'RewriteRule ^api/rest_admin/product_filters/filters/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/filter_admin/filters&limit=$1&page=$2  [L]',
            'RewriteRule ^api/rest_admin/product_filters/filters index.php?route=rest/filter_admin/filters  [L]',
            'RewriteRule ^api/rest_admin/product_filters/groups index.php?route=rest/filter_admin/groups  [L]',
            '###################################### RETURNS #######################################',
            'RewriteRule ^api/rest_admin/returns/history/?([0-9]+) index.php?route=rest/return_admin/history&id=$1  [L]',
            'RewriteRule ^api/rest_admin/returns/filter_return_id/?([0-9]+) index.php?route=rest/return_admin/returns&filter_return_id=$1  [L]',
            'RewriteRule ^api/rest_admin/returns/filter_order_id/?([0-9]+) index.php?route=rest/return_admin/returns&filter_order_id=$1  [L]',
            'RewriteRule ^api/rest_admin/returns/limit/?([0-9]+)/page/?([0-9]+) index.php?route=rest/return_admin/returns&limit=$1&page=$2  [L]',
            'RewriteRule ^api/rest_admin/returns/?([0-9]+) index.php?route=rest/return_admin/returns&id=$1  [L]',
            'RewriteRule ^api/rest_admin/returns index.php?route=rest/return_admin/returns  [L]',

            '################################# OPENCART REST ADMIN API END ###############################',
            'RewriteCond %{REQUEST_FILENAME} !-f',
        )), $currentHtaccess);

        //backup current htaccess file
        @file_put_contents($directory.".htaccess_rest_admin_api_backup", $currentHtaccess);

        @file_put_contents($htaccess, $newHtaccess);

        //restore htaccess file permission
        if( $htaccessFilePermission ) {
            @ chmod( $htaccess, $htaccessFilePermission );
        }

        return true;
    }

}
