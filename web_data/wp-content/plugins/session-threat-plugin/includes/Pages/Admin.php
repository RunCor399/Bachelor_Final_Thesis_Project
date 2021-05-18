<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\Pages;

class Admin{

    public function register(){
		add_action('admin_menu', array($this, 'add_admin_pages'));
	}

	public function add_admin_pages(){
		add_menu_page('Session Threat Admin Page', 'Session Threat Admin', 'manage_options','sessionThreat_plugin', array('Inc\Pages\Admin', 'test_admin_index'), '', 110);
  	}

  	public static function test_admin_index(){
		require_once PLUGIN_PATH . 'templates/admin.php';
	}
}

?>