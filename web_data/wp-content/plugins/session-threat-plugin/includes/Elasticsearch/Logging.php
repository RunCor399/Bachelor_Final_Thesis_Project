<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\Elasticsearch;

use Elasticsearch\ClientBuilder;

class Logging {
    private $elastic_client;

    public function register(){
		self::$elastic_client = ClientBuilder::create()->build();
	}

    public static function index_session($sessions_data){
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
                    'account_type'     => $updated_session[$session]["account_type"],
                    'user_agent' => $updated_session[$session]["user_agent"],
                    'session_timestamp' => $updated_session[$session]["session_timestamp"],
                    'last_request_datetime' => date("c", $updated_session[$session]["last_request_timestamp"]),
                    'last_request_timestamp' => $updated_session[$session]["last_request_timestamp"],
                    'php_session_ids' => array($updated_session[$session]["php_session_ids"]),
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
    
        $responses = self::$elastic_client->bulk($params);
    }
}

?>