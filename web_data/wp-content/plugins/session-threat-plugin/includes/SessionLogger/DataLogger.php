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
use Inc\Elasticsearch\Logging;
use Inc\Proactivity\BlacklistController;


class DataLogger{

    public function register(){
		add_action('template_redirect', array($this, 'collect_data'));
	}

    function collect_data(){
        if($this->drop_favicon_request($_SERVER["REQUEST_URI"])){
          return;
        }
        
        //session
        $email = $this->retrieve_email();
        $user_ID = $this->get_user_ID();
        $ip = $_SERVER['REMOTE_ADDR'];
        $user_agent = $_SERVER['HTTP_USER_AGENT'];
        $last_request_timestamp = time();
        $last_request_datetime = date("c");
        
        $session_duration = $this->get_session_duration();



        
        if(isset($_SERVER["HTTP_X_FORWARDED_FOR"])){
            $ip = $_SERVER["HTTP_X_FORWARDED_FOR"];
        }

        $this->set_session_cookie(rand());
        $this->setup_visitor_cookie($user_agent.$ip);

        //check blacklist
        if(BlacklistController::check_ip($ip, $_COOKIE["visitor_id"])){       
          global $wp_query;
          $wp_query->set_404();
          status_header( 404 );
          get_template_part( 404 ); exit();
          return;
        }

        $script_name = $_SERVER["REQUEST_URI"];
        $http_host = $_SERVER['HTTP_HOST'];
        $request_params = $this->collect_request_params();

        $cookies = $request_params["cookies"];
        $get_params = $request_params["get_params"];
        $post_params = $request_params["post_params"];
        $http_referer = $request_params["http_referer"];
        
   
        $request_data = array("ip" => $ip, "email" => $email, "cookies" => $cookies, "http_host" => $http_host, "script_name" => $script_name,
                              "get_params" => $get_params, "post_params" => $post_params, "http_referer" => $http_referer, "timestamp" => date("c"));

        $elastic_request = $this->create_request($request_data);


        $threat_response = ClientAPI::send_threat_data("http://137.204.78.99:8001/session_evaluator/request_api.php", $elastic_request);
        $threat_response = json_decode($threat_response["body"], true);
        

        
        //threat score check
        BlacklistController::check_threat_score($_COOKIE["visitor_id"], $ip);

        //move compute threat status here, remove session completely
	      $threat_status = Session::compute_threat_status($threat_response["threat_score"], $threat_response["breach_flag"]);
        $session_cookie = $_COOKIE['session_cookie'];

        

        $session_db_data = array("user_id" => $user_ID, "session_id" => $_COOKIE["visitor_id"], "threat_score" => $threat_response["threat_score"], "threat_status" => $threat_status,
        "breach_flag" => $threat_response["breach_flag"], "user_agent" => $user_agent, "session_duration" => $session_duration, "last_request_datetime" => $last_request_datetime,
         "ip_address" => $ip, "cookie" => $cookies);


        if(isset($_COOKIE["visitor_id"]) && !is_null($_COOKIE["visitor_id"])){
            $elastic_sessions = DBProcedures::choose_action($session_db_data);
        }

        DBProcedures::create_request($request_data);
        
        
        $elastic_request["location"] = $threat_response["location"];
        $this->log_to_elasticsearch($elastic_sessions, $elastic_request);
    }

    public function set_session_cookie($random_int){
        if(!isset($_COOKIE['session_cookie'])){
            $session_cookie = hash("sha256", $random_int, false);
            setcookie("session_cookie", $session_cookie, time() + 60*60*10*24, "/"); 
        }
    }
    
    public function drop_favicon_request($script_name){
      return $script_name == "/favicon.ico";
    }

    private function create_session($session_data){

        //might be static
        return $user_session->log_user_session();
    }

    private function create_request($request_data){
        //might be static
        $request = new Request($request_data['ip'], $request_data['email'], $request_data['cookies'], $request_data['http_host'],
                               $request_data['script_name'], $request_data['get_params'], $request_data['post_params'], $request_data['http_referer']);

        $request_array = $request->log_request();

        return $request_array;
    }

    private function log_to_elasticsearch($elastic_sessions, $elastic_request){
        if(!is_null($elastic_sessions)){
          Logging::index_session($elastic_sessions);
        }
        
        Logging::index_request($elastic_request);
    }

    private function collect_request_params(){
        $cookies = null;
        $get_params = null;
        $post_params = null;
        $http_referer = null;

        if(!empty($_COOKIE)){
            $cookies = $_COOKIE;
	          $cookies_array = array();

            foreach($cookies as $key => $value){
                $cookies_array[$key] = $value;
            }
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

        return array("cookies" => $cookies_array, "get_params" => $get_params, "post_params" => $post_params, "http_referer" => $http_referer);
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

    private function get_session_duration(){
        return is_user_logged_in() ? time() - LastLogIn::get_user_last_login(wp_get_current_user()) : null;
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
