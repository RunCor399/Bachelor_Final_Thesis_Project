<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\Base;

class LastLogIn{

    public function register(){
		add_action('wp_login', array($this, 'user_last_login'), 10, 2);
	}

	function user_last_login( $user_login, $user ) {
        update_user_meta( $user->ID, '_last_login', time() );
    }

    public static function get_user_last_login($user){
        $last_login = get_user_meta( $user->ID, '_last_login', true );

        return $last_login;
    }
}

?>