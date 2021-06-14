<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\Elasticsearch;

use Elasticsearch\ClientBuilder;

class Logging {
    private static $elastic_client;

    public function register(){
        $host = [
            'elasticsearch:9200'
        ];
        
		self::$elastic_client = ClientBuilder::create()->setHosts($host)->build();
	}

    public static function index_session($session_data){
                $params['body'][] = [
                    'index' => [
                        '_index' => 'sessions',
                    ]
                ];
    

                $params['body'][] = [             
                    'ip_addresses' => $session_data["ip_addresses"],
                    'user_agent' => $session_data["user_agent"],
                    'session_duration' => $session_data["session_duration"],
                    'last_request_datetime' => date("c", $session_data["last_request_datetime"]),
                    'wp_session_cookie' => $session_data["wp_session_cookie"],
                    'email' => $session_data["email"],
                    'session_ID' => $session_data["session_ID"],
                    'threat_status' => $session_data["threat_status"],
                    'threat_score' => $session_data["threat_score"],
                    'breach_flag' => $session_data["breach_flag"],
                    'page_loads' => $session_data["page_loads"],
                    'timestamp' => $session_data["timestamp"]
                ];
    
        $responses = self::$elastic_client->bulk($params);
    }

    public static function index_request($request_data){

            $params['body'][] = [
                'index' => [
                    '_index' => 'requests',
                ]
            ];
            
            if(!is_null($request_data["location"])){
                $params['body'][] = [
                    'ip_address' => $request_data["ip_address"],
                    'email' => $request_data["email"],
                    'cookies' => $request_data["cookies"],
                    'http_host'  => $request_data["http_host"],
                    'script_name' => $request_data["script_name"],
                    'get_params' => array($request_data["get_params"]),
                    'post_params' => array($request_data["post_params"]),
                    'http_referer' => $request_data["http_referer"],
                    'timestamp' => $request_data["timestamp"],
                    'location' => $request_data["location"]
                ];
            }
            else{
                $params['body'][] = [
                    'ip_address' => $request_data["ip_address"],
                    'email' => $request_data["email"],
                    'cookies' => array($request_data["cookies"]),
                    'http_host'  => $request_data["http_host"],
                    'script_name' => $request_data["script_name"],
                    'get_params' => array($request_data["get_params"]),
                    'post_params' => array($request_data["post_params"]),
                    'http_referer' => $request_data["http_referer"],
                    'timestamp' => $request_data["timestamp"]
                ];
            }

        $responses = self::$elastic_client->bulk($params);
    }
}

?>
