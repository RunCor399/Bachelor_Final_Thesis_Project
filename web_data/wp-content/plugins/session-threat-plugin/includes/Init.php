<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc;

use Inc\Base\LastLogIn;

final class Init{

    public static function get_services() {
        return [
            Pages\Admin::class,
            Base\Enqueue::class,
            Base\SettingsLinks::class,
            Base\LastLogIn::class,
            SessionLogger\DataLogger::class
        ];
    }

    //calls register method inside each instantiated class
    public static function register_services(){
        foreach(self::get_services() as $class){
            $service = self::instantiate($class);

            if(method_exists($service, 'register')){
                $service->register();
            }
        }
    }

    //initialize each class
    private static function instantiate($class){
        $service = new $class();

        return $service;
    }
}




?>