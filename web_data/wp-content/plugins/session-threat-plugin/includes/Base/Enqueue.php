<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\Base;

class Enqueue{

    public function register(){
		add_action('admin_enqueue_scripts', array($this, 'admin_enqueue'));
        add_action('wp_enqueue_scripts', array($this, 'wp_enqueue'));
	}

    function admin_enqueue(){
		wp_enqueue_script('admin_plugin_js', PLUGIN_URL . 'public/js/hello.js');
	}

    function wp_enqueue(){
        wp_enqueue_script('wp_plugin_js', PLUGIN_URL . 'public/js/hello.js');
    }

}

?>