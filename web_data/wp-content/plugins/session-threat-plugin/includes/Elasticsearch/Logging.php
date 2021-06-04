<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\Elasticsearch;

use Elasticsearch\ClientBuilder;

class Logging {

    public function register(){
		//global $elastic_client = ClientBuilder::create()->build();
	}

    public static function index_session($sessions_data){
        $host = [
            'elasticsearch:9200'
        ];

	    $elastic_client = ClientBuilder::create()->setHosts($host)->build();

        foreach($sessions_data as $updated_session){
            $ip_addresses = array();
    
            foreach($updated_session as $session => $data) {
                $params['body'][] = [
                    'index' => [
                        '_index' => 'sessions',
                    ]
                ];
    
                foreach($updated_session[$session]["ip_addresses"] as $ip){
                    array_push($ip_addresses, $ip);
                }
	

                $params['body'][] = [
                    'ip_addresses' => array($ip_addresses),
                    'user_agent' => $updated_session[$session]["user_agent"],
                    'session_timestamp' => $updated_session[$session]["session_timestamp"],
                    'last_request_datetime' => date("c", $updated_session[$session]["last_request_timestamp"]),
                    'last_request_timestamp' => $updated_session[$session]["last_request_timestamp"],
                    'wp_session_cookie' => array($updated_session[$session]["wp_session_cookie"]),
                    'email' => $updated_session[$session]["email"],
                    'cookie' => $updated_session[$session]["cookie"],
                    'threat_status' => $updated_session[$session]["threat_status"],
                    'threat_score' => $updated_session[$session]["threat_score"],
                    'breach_flag' => $updated_session[$session]["breach_flag"],
                    'page_loads_count' => $updated_session[$session]["page_loads_count"],
                    'timestamp' => $updated_session[$session]["timestamp"]
                ];

            }
        }
    
        $responses = $elastic_client->bulk($params);
    }

    public static function index_request($request_data){
        $host = [
            'elasticsearch:9200'
        ];
    
        $elastic_client = ClientBuilder::create()->setHosts($host)->build();

            $params['body'][] = [
                'index' => [
                    '_index' => 'requests',
                ]
            ];
            
            if(!is_null($request["location"])){
                $params['body'][] = [
                    'ip_address' => $request["ip_address"],
                    'email' => $request["email"],
                    'cookies' => array($request["cookies"]),
                    'http_host'  => $request["http_host"],
                    'script_name' => $request["script_name"],
                    'get_params' => array($request["get_params"]),
                    'post_params' => array($request["post_params"]),
                    'http_referer' => $request["http_referer"],
                    'timestamp' => $request["timestamp"],
                    'location' => $request["location"]
                ];
            }
            else{
                $params['body'][] = [
                    'ip_address' => $request["ip_address"],
                    'email' => $request["email"],
                    'cookies' => array($request["cookies"]),
                    'http_host'  => $request["http_host"],
                    'script_name' => $request["script_name"],
                    'get_params' => array($request["get_params"]),
                    'post_params' => array($request["post_params"]),
                    'http_referer' => $request["http_referer"],
                    'timestamp' => $request["timestamp"]
                ];
            }
    
        
        $responses = $elastic_client->bulk($params);
    }
}

?>
