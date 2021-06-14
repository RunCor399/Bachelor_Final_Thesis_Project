<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\SessionLogger;

class ClientAPI {

    public static function send_threat_data($url, $request){
        $args = array(
            'headers' => array(
            'Content-Type'   => 'application/json',
            ),
            'body'      => json_encode($request),
            'method'    => 'PUT'
        );

        return wp_remote_post($url, $args);
    }

}