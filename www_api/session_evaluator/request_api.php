<?php


require_once("evaluator.php");
require_once("geoip/geoip2.phar");

use GeoIp2\Database\Reader;

$request_json_data = file_get_contents('php://input');
$request_data = json_decode($request_json_data, true);


$wordlist_paths = array("wordlists/blacklist_get_keys.txt",
                        "wordlists/blacklist_get_values.txt",
                        "wordlists/blacklist_post_keys.txt",
                        "wordlists/blacklist_post_values.txt",
                        "wordlists/blacklist_user.txt",
                        "wordlists/file_extensions.txt",
                        "wordlists/page_names.txt",
                        "wordlists/whitelist_cookie_keys.txt");

$evaluator = new Evaluator($wordlist_paths);
$threat_score = $evaluator->analyze_request($request_data);
$breach_flag = $evaluator->get_breach_flag();


echo json_encode(compute_evaluation_result($threat_score, $request_data, $breach_flag));


function compute_evaluation_result($threat_score, $request_data, $breach_flag){
    $location = geolocate_ip($request_data["ip_address"]);
     // $location = null;

    if(is_null($location)){
        return array("threat_score" => $threat_score, "breach_flag" => $breach_flag, "location" => null);
    }
    else{
        return array("threat_score" => $threat_score, "breach_flag" => $breach_flag, "location" => array("lat" => $location["lat"], "lon" => $location["lon"]));
    }
    
}

function geolocate_ip($ip_address){
    $reader = new Reader('geoip/GeoLite2-City.mmdb');

    try {
        $record = $reader->city($ip_address);

    } catch (GeoIp2\Exception\AddressNotFoundException $e) {
        return null;
    }

    $country = $record->country->name;
    $city = $record->city->name;
    $latitude = $record->location->latitude;
    $longitude = $record->location->longitude;

    $location = array("lat" => $latitude, "lon" => $longitude);

    return $location;
}
?>
