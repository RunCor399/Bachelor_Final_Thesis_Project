<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\SessionLogger;

use Inc\Base\LastLogIn;
use Inc\Database\DBClient;
use Inc\SessionLogger\Request;
use Inc\SessionLogger\Session;
use Inc\SessionLogger\ClientAPI;
use Inc\Database\DBProcedures;

class DataLogger{

    public function register(){
		add_action('template_redirect', array($this, 'collect_data'));
        //add_action('wp', array($this, 'collect_data'));
        //add_action('template_redirect', 'Inc\Database\DBClient::test_db');
	}

    function collect_data(){
        //setcookie("test", "abc", time() + 60*60, "/");
        //create class to collect data and return that data to this one

        //session
        $email = $this->retrieve_email();
        $user_ID = $this->get_user_ID();
        $ip = $_SERVER['REMOTE_ADDR'];
        $user_agent = $_SERVER['HTTP_USER_AGENT'];
        $last_request_timestamp = time();
        $session_timestamp = $this->get_session_timestamp();
        
        if(isset($_SERVER["HTTP_X_FORWARDED_FOR"])){
            $ip = $_SERVER["HTTP_X_FORWARDED_FOR"];
        }

        //use something else instead of random or store first time generated random in db to rebuild and check the cookie
        $this->set_session_cookie(rand());
        $this->setup_visitor_cookie($user_agent.$ip);

        //request
        $script_name = $_SERVER["REQUEST_URI"];
        $http_host = $_SERVER['HTTP_HOST'];
        $request_params = $this->collect_request_params();

        $cookies = $request_params["cookies"];
        $get_params = $request_params["get_params"];
        $post_params = $request_params["post_params"];
        $http_referer = $request_params["http_referer"];
        

        $request_data = array("ip" => $ip, "email" => $email, "cookies" => $cookies, "http_host" => $http_host,
        "script_name" => $script_name, "get_params" => $get_params, "post_params" => $post_params, "http_referer" => $http_referer);

        $request_array = $this->create_request($request_data);

        //api call to receive data of evaluator
        $threat_response = array("threat_score" => 0, "breach_flag" => false);
        //$threat_response = ClientAPI::send_threat_data("http://137.204.78.99:8001/session_evaluator/request_api.php", $request_array);
        //$threat_response = json_decode($threat_response["body"], true);

	    //$threat_status = Session::compute_threat_status($threat_response["threat_score"], $threat_response["breach_flag"]);
        $threat_status = "ok";

        $session_cookie = $_COOKIE['session_cookie'];

        $session_data = array("ip" => $ip, "user_agent" => $user_agent, "last_request_timestamp" => $last_request_timestamp, "threat_score" => 0,
        "breach_flag" => false, "email" => $email, "session_timestamp" => $session_timestamp, "wp_session_cookie" => array($session_cookie));


        $session_db_data = array("user_id" => $user_ID, "session_id" => $_COOKIE["visitor_id"], "threat_score" => 0, "threat_status" => $threat_status,
        "breach_flag" => false, "user_agent" => $user_agent, "session_timestamp" => $session_timestamp, "ip_address" => $ip, "cookie" => $cookies);



        if(isset($_COOKIE["visitor_id"])){
            DBProcedures::choose_action($session_db_data);
        }

	$this->create_session($session_data);
        
    }

    public function set_session_cookie($random_int){
        if(!isset($_COOKIE['session_cookie'])){
            $session_cookie = hash("sha256", $random_int, false);
            setcookie("session_cookie", $session_cookie, time() + 60*60*10*24, "/"); 
        }
    }

    private function create_session($session_data){
        $user_session = new Session($session_data['ip'], $session_data['user_agent'], $session_data['last_request_timestamp'], $session_data['threat_score'],
                                    $session_data['breach_flag'], $_COOKIE['visitor_id'], $session_data['email'], $session_data['session_timestamp'], $session_data['wp_session_cookie']);
        
        //might be static
        $updated_sessions = $user_session->log_user_session();
    }

    private function create_request($request_data){
        //might be static
        $request = new Request($request_data['ip'], $request_data['email'], $request_data['cookies'], $request_data['http_host'],
                               $request_data['script_name'], $request_data['get_params'], $request_data['post_params'], $request_data['http_referer']);

        $request_array = $request->log_request();

        return $request_array;
    }

    private function collect_request_params(){
        $cookies = null;
        $get_params = null;
        $post_params = null;
        $http_referer = null;

        if(!empty($_COOKIE)){
            $cookies = $_COOKIE;
        }
        if(!empty($_GET)){
            $get_params = $_GET;
        }
        if(!empty($_POST)){
            $post_params = $_POST;
        }

        if(isset($_SERVER["HTTP_REFERER"])){
            $http_referer = $_SERVER["HTTP_REFERER"];
        }

        return array("cookies" => $cookies, "get_params" => $get_params, "post_params" => $post_params, "http_referer" => $http_referer);
    }

    private function retrieve_email(){
        if(is_user_logged_in()){
            $user = wp_get_current_user();

            return $user->user_email;
        }
        else{
            return null;
        }
    }

    private function get_session_timestamp(){
        if(is_user_logged_in()){
            $user = wp_get_current_user();
            $session_timestamp = time() - LastLogIn::get_user_last_login($user);

            $time = $session_timestamp / 60;
            $hours = floor($time / 60);
            $minutes = ($time % 60);
            $seconds = ($session_timestamp - $minutes * 60);

            $duration = $hours.":".$minutes.":".$seconds;
            return $duration;
        }
        else{
            return null;
        }
    }

    private function get_user_ID(){
        if(is_user_logged_in()){
            $user = wp_get_current_user();
            
            return $user->ID;
        }
        else{
            return null;
        }
    }

    private function setup_visitor_cookie($visitor_id){
        $cookie = hash("sha256", $visitor_id, false);

        if(!isset($_COOKIE["visitor_id"])){
            setcookie("visitor_id", $cookie, time() + 60*60*24, "/"); 
        }
        else{
            if($cookie != $_COOKIE["visitor_id"]){
                unset($_COOKIE['visitor_id']); 
                setcookie('visitor_id', $cookie, time() + 60*60*24, "/");
            }
        }
    }
}

?>
