<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\Base;

class SessionThreatPluginActivate{
    public static function activate(){
        //$sessionThreatPlugin->custom_post_type();
        flush_rewrite_rules();
    }
}




?>