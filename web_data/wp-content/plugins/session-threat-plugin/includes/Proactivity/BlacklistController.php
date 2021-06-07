<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\Proactivity;

use Inc\Database\DBClient;

class BlacklistController{

    public static function check_ip($ip_address){
        $result = DBClient::search_blacklisted_ip($ip_address);

        var_dump($result);
    }
}

