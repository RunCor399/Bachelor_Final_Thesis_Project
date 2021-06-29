<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\Proactivity;

use Inc\Database\DBClient;


class BlacklistController{

    public static function check_ip($ip_address, $session_ID){
        $result = DBClient::search_blacklisted_ip($ip_address);


        if(empty($result)){
          return 0;
        }
        
        //
        if(self::check_validity($result[0]["blacklist_timestamp"])){
          DBClient::delete_ip_from_blacklist($ip_address);
          
          $threat_ID = DBClient::get_threat_by_session($session_ID);
          DBClient::update_threat($threat_ID, 0, "safe_user", false);


          
          return 0;
        }

        return 1;
    }
    
    public static function check_threat_score($session_ID, $ip_address){
      $result = DBClient::get_threat_data_by_ID(DBClient::get_threat_by_session($session_ID));
      
      $threat_score = $result[0]["threat_score"];

      if((int) $threat_score > 2000){
        DBClient::insert_blacklist_ip($ip_address, date("Y-m-d H:i:s", time()));
      }
    }
    
    //HIGHER THREAT SCORE AND TIME (1 DAY LOCK)
    private static function check_validity($timestamp){
        return time() - strtotime($timestamp) >= 3600; 
    }
}

