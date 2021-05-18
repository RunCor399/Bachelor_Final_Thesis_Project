<?php

namespace Inc\SessionLogger;

class Request {
    private $ip;
    private $email;
    private $cookies;
    private $http_host;
    private $script_name;
    private $get_params;
    private $post_params;
    private $http_referer;

    public function __construct($ip, $email, $cookies, $http_host, $script_name, $get_params, $post_params, $http_referer){
        $this->ip = $ip;
        $this->email = $email;
        $this->cookies = $cookies;
        $this->http_host = $http_host;
        $this->script_name = $script_name;
        $this->get_params = $get_params;
        $this->post_params = $post_params;
        $this->http_referer = $http_referer;
    }

    public function log_request(){
        $requests_data = json_decode(file_get_contents(PLUGIN_PATH . "includes/SessionLogger/requests.json"), true);
        $request_data = $this->build_json_request();

        if(empty($requests_data)){
            $requests_data = array();
        }

        array_push($requests_data, $request_data);
        $requests_json_data = json_encode($requests_data, JSON_PRETTY_PRINT);


        file_put_contents(PLUGIN_PATH . "includes/SessionLogger/requests.json", $requests_json_data);

        return $request_data;
    }

    private function build_json_request(){
        $cookies = array();
        $get_params = array();
        $post_params = array();

        if($this->cookies != null){
            foreach($this->cookies as $cookie_key => $cookie_value){
                $cookies[$cookie_key] = $cookie_value;
            }
        }
        else{
            $cookies = null;
        }
        
        if($this->get_params != null){
            foreach($this->get_params as $get_key => $get_value){
                $get_params[$get_key] = $get_value;
            }
        }
        else{
            $get_params = null;
        }


        if($this->post_params != null){
            foreach($this->post_params as $post_key => $post_value){
                $post_params[$post_key] = $post_value;
            }
        }
        else{
            $post_params = null;
        }
        
        return array("ip_address" => $this->ip, "email" => $this->email,
                    "cookies" => $cookies,
                    "http_host" => $this->http_host,
                    "script_name" => $this->script_name,
                    "get_params" => $get_params,
                    "post_params" => $post_params,
                    "http_referer" => $this->http_referer,
                    "timestamp" => date("c")
                );
    }
}

?>