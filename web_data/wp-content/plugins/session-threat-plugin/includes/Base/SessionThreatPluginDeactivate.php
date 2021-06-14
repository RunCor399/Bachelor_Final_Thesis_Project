<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\Base;

class SessionThreatPluginDeactivate{
    public static function deactivate(){
        flush_rewrite_rules();
    }
}

?>