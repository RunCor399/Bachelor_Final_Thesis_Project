<?php

/**
 *
 * @since             1.0.0
 * @package           SessionThreatPlugin
 *
 * @wordpress-plugin
 * Plugin Name:       WordPress Session Tracker
 * Description:       Session Tracker and Threat Evaluator.
 * Version:           1.0.0
 * Author:            Colotti Manuel Enrique
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       session-tracker and threat evaluator (STaTE)
 * Domain Path:       /
 */


if ( ! defined( 'ABSPATH' ) ) {
	die;
}


define( 'SESSION_TRACKER_VERSION', '1.0.0' );


if (file_exists(dirname(__FILE__) . '/vendor/autoload.php')) {
	require_once dirname(__FILE__) . '/vendor/autoload.php';
}

define('PLUGIN_PATH', plugin_dir_path(__FILE__));
define('PLUGIN_URL', plugin_dir_url(__FILE__));
define('PLUGIN', plugin_basename(__FILE__));
define('THREAT_EVALUATOR_API', "http://137.204.78.99:8001/session_evaluator/request_api.php");


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



?>