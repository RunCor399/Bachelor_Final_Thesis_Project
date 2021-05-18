<?php

/**
 * The plugin bootstrap file
 *
 * This file is read by WordPress to generate the plugin information in the plugin
 * admin area. This file also includes all of the dependencies used by the plugin,
 * registers the activation and deactivation functions, and defines a function
 * that starts the plugin.
 *
 * @link              http://example.com
 * @since             1.0.0
 * @package           SessionThreatPlugin
 *
 * @wordpress-plugin
 * Plugin Name:       WordPress Session Tracker
 * Plugin URI:        http://example.com/session-tracker-uri/
 * Description:       Session Tracker description.
 * Version:           1.0.0
 * Author:            Colotti Manuel Enrique
 * Author URI:        http://example.com/
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       session-tracker
 * Domain Path:       /languages
 */


// If this file is called directly, abort.
if ( ! defined( 'ABSPATH' ) ) {
	die;
}

/**
 * Currently plugin version.
 * Start at version 1.0.0 and use SemVer - https://semver.org
 * Rename this for your plugin and update it as you release new versions.
 */
define( 'SESSION_TRACKER_VERSION', '1.0.0' );


if (file_exists(dirname(__FILE__) . '/vendor/autoload.php')) {
	require_once dirname(__FILE__) . '/vendor/autoload.php';
}

define('PLUGIN_PATH', plugin_dir_path(__FILE__));
define('PLUGIN_URL', plugin_dir_url(__FILE__));
define('PLUGIN', plugin_basename(__FILE__));


use Inc\Base\SessionThreatPluginActivate;
use Inc\Base\SessionThreatPluginDeactivate;


function activate_session_threat_plugin(){
	SessionThreatPluginActivate::activate();
}

function deactivate_session_threat_plugin(){
	SessionThreatPluginDeactivate::deactivate();
}



register_activation_hook( __FILE__, 'activate_session_threat_plugin' );
register_deactivation_hook( __FILE__, 'deactivate_session_threat_plugin');

if ( class_exists('Inc\\Init')){
	Inc\Init::register_services();
}






/*use Inc\Base\SessionThreatPluginActivate;
use Inc\Base\SessionThreatPluginDeactivate;
use Inc\Pages\Admin;

class SessionThreatPlugin{

	public $plugin;

	function __construct(){
		$this->plugin = plugin_basename(__FILE__);

		add_action('init', array($this, 'custom_post_type'));
	}

	function register(){
		//cant call static method, solve
		add_action('admin_menu', array('Inc\AdminPage', 'add_admin_pages'));
		
		add_filter("plugin_action_links_$this->plugin", array($this, 'settings_link'));
	}

	function register_wp_scripts(){
		add_action('wp_enqueue_scripts', array($this, 'wp_enqueue'));

		//in case of static method, wp_enqueue must be static too
		//add_action('wp_enqueue_scripts', array('SessionThreatPlugin', 'wp_enqueue'));
	}

	function register_admin_scripts(){
		add_action('admin_enqueue_scripts', array($this, 'admin_enqueue'));
	}

	function activate() {
		//require_once plugin_dir_path(__FILE__) . 'includes/session-threat-plugin-activate.php';
		SessionThreatPluginActivate::activate($this);
	}

	function deactivate(){
		//require_once plugin_dir_path(__FILE__) . 'includes/session-threat-plugin-deactivate.php';
		SessionThreatPluginDeactivate::deactivate($this);
	}
	
	

	function uninstall(){

	}


	function wp_enqueue(){
		wp_enqueue_script('wp_plugin_js', plugins_url('public/js/hello.js', __FILE__));
	}

	function admin_enqueue(){
		wp_enqueue_script('admin_plugin_js', plugins_url('public/js/hello.js', __FILE__));
	}

	function custom_post_type(){
		register_post_type('book', ['public' => true, 'label' => 'Books']);
	}

	

	

	public function settings_link($links){
		//all links shown in plugin admin page
		$settings_link = '<a href="admin.php?page=sessionThreat_plugin">Admin Page</a>';
		array_push($links, $settings_link);

		return $links;
	}
}


if ( class_exists('SessionThreatPlugin')){
	$sessionThreatPlugin = new SessionThreatPlugin();

	//$sessionThreatPlugin->register_admin_scripts();
	$sessionThreatPlugin->register_wp_scripts();
	$sessionThreatPlugin->register();
}

//Activation
register_activation_hook( __FILE__, array($sessionThreatPlugin, 'activate') );
register_deactivation_hook( __FILE__, array($sessionThreatPlugin, 'deactivate') );*/



