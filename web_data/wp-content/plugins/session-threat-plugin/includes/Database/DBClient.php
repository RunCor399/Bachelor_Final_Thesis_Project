<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\Database;


class DBClient {
    private static $wpdb;

    public static function register(){
        self::$wpdb = $GLOBALS['wpdb'];
    }

    public static function test_db(){
        
    }

    //TRANSACTIONS

    public static function start_transaction(){
        self::$wpdb->show_errors();
        self::$wpdb->query('START TRANSACTION');
    }

    public static function commit_transaction(){
        self::$wpdb->query('COMMIT');
    }

    public static function rollback_transaction(){
        self::$wpdb->query('ROLLBACK');
    }

    public static function disable_foreign_checks(){
        self::$wpdb->query('set foreign_key_checks = 0');
    }

    public static function enable_foreign_checks(){
        self::$wpdb->query('set foreign_key_checks = 1');
    }

    //SEARCH

    public static function search_session_id($session_id){
        $sql = "SELECT s.session_ID FROM `session` s WHERE s.session_ID = %s";

        $query = self::$wpdb->prepare($sql, $session_id);
        $result = self::$wpdb->get_results($query, ARRAY_A);
        
        return self::check_search_result($result);
    }

    
    public static function compare_session_id_by_user_id($session_id, $user_id){
        $session_ids = self::get_session_id_by_user_id($user_id);

        if(is_null($session_ids)){
            return false;
        }

        foreach($session_ids as $id){
            if($session_id == $id){
                return true;
            }
        }

        return false;
    }

    //GET

    public static function get_session_id_by_user_id($user_id){
        $sql = "SELECT su.session_ID AS session_ID
                FROM `session_user` su
                WHERE su.user_ID = %d";

        $query = self::$wpdb->prepare($sql, $user_id);
        $result = self::$wpdb->get_results($query, ARRAY_A);

        return self::check_select_result($result);
    }

    public static function get_user_id_by_session_id($session_ID){
        $sql = "SELECT su.user_ID
                FROM `session_user` su
                WHERE su.session_ID = %s";

        $query = self::$wpdb->prepare($sql, $session_ID);
        $result = self::$wpdb->get_results($query, ARRAY_A);

        return self::check_select_result($result);
    }

    public static function get_ip_id_by_session_id($session_ID){
        $sql = "SELECT si.ip_ID 
                FROM session_ip si
                WHERE si.session_ID = %s";

        $query = self::$wpdb->prepare($sql, $session_ID);
        $result = self::$wpdb->get_results($query, ARRAY_A);

        return self::check_select_result($result);
    }

    public static function get_ip_id_by_ip_value($ip_value){
        $sql = "SELECT i.ip_ID 
                FROM ip_address i
                WHERE i.ip_value = %s";

        $query = self::$wpdb->prepare($sql, $ip_value);
        $result = self::$wpdb->get_results($query, ARRAY_A);

        return self::check_select_result($result);
    }

    public static function get_all_cookies_by_session($session_ID){
        $sql = "SELECT sc.cookie_ID AS cookie_ID, c.cookie_name AS cookie_name, c.cookie_value AS cookie_value
                FROM session_cookie sc, cookie c
                WHERE sc.session_ID = %s AND sc.cookie_ID = c.cookie_ID";

        $query = self::$wpdb->prepare($sql, $session_ID);
        $result = self::$wpdb->get_results($query, ARRAY_A);

        return self::check_select_result($result);       
    }

    public static function get_cookie_count_by_session($session_ID, $cookie_name, $cookie_value){
        $sql = "SELECT COUNT(sc.cookie_ID) AS cookie_count
                FROM session_cookie sc, cookie c
                WHERE sc.session_ID = %s AND c.cookie_name = %s AND c.cookie_value = %s AND sc.cookie_ID = c.cookie_ID";

        $query = self::$wpdb->prepare($sql, array($session_ID, $cookie_name, $cookie_value));
        $result = self::$wpdb->get_results($query, ARRAY_A);

        return $result[0]["cookie_count"];
    }

    public static function get_cookie_id_by_name_and_session($session_ID, $cookie_name){
        $sql = "SELECT c.cookie_ID AS cookie_ID
                FROM session_cookie sc, cookie c
                WHERE sc.session_ID = %s AND c.cookie_name = %s AND sc.cookie_ID = c.cookie_ID";

        $query = self::$wpdb->prepare($sql, array($session_ID, $cookie_name));
        $result = self::$wpdb->get_results($query, ARRAY_A);

        return $result["cookie_ID"];
    }

    public static function get_threat_by_session($session_ID){
        $sql = "SELECT s.threat_ID  AS threat_ID
                FROM session s
                WHERE s.session_ID = %s";

        $query = self::$wpdb->prepare($sql, $session_ID);
        $result = self::$wpdb->get_results($query, ARRAY_A);

        return $result[0]["threat_ID"];
    }

    public static function get_matching_ip_count($ip_value, $session_ID){
        $sql = "SELECT COUNT(i.ip_ID) AS ip_count
                FROM session_ip si, ip_address i, session s
                WHERE i.ip_value = %s  AND s.session_ID = %s AND i.ip_ID = si.ip_ID AND si.session_ID = s.session_ID";

        $query = self::$wpdb->prepare($sql, array($ip_value, $session_ID));
        $result = self::$wpdb->get_results($query, ARRAY_A);

        return $result[0]["ip_count"];
    }

    public static function get_threat_data_by_id($threat_ID){
        $sql = "SELECT t.threat_score, t.threat_status, t.breach_flag
                FROM threat t
                WHERE t.threat_ID = %d";

        $query = self::$wpdb->prepare($sql, $threat_ID);
        $result = self::$wpdb->get_results($query, ARRAY_A);

        return self::check_select_result($result);
    }


    public static function insert_threat($threat_score, $threat_status, $breach_flag){
        $result = self::$wpdb->insert('threat', array('threat_score' => $threat_score, 'threat_status' => $threat_status, 'breach_flag' => $breach_flag));

        return self::check_insert_result($result);
    }

    public static function insert_session($session_ID, $threat_ID, $user_agent, $session_timestamp){
        $result = self::$wpdb->insert('session', array('session_ID' => $session_ID, 'threat_ID' => $threat_ID, 'user_agent' => $user_agent, 'session_timestamp' => $session_timestamp));

        return self::check_insert_result($result);
    }

    public static function insert_session_user($session_ID, $user_ID){
        $result = self::$wpdb->insert('session_user', array('session_ID' => $session_ID, 'user_ID' => $user_ID));

        return self::check_insert_result($result);
    }

    public static function insert_cookie($cookie_name, $cookie_value){
        $result = self::$wpdb->insert('cookie', array('cookie_name' => $cookie_name, 'cookie_value' => $cookie_value));

        return self::check_insert_result($result);
    }

    public static function insert_session_cookie($cookie_ID, $session_ID){
        $result = self::$wpdb->insert('session_cookie', array('cookie_ID' => $cookie_ID, 'session_ID' => $session_ID));

        return self::check_insert_result($result);
    }

    public static function insert_ip_address($ip_value){
        $result = self::$wpdb->insert('ip_address', array('ip_value' => $ip_value));

        return self::check_insert_result($result);
    }

    public static function insert_session_ip($session_ID, $ip_ID){
        $result = self::$wpdb->insert('session_ip', array('session_ID' => $session_ID, 'ip_ID' => $ip_ID));

        return self::check_insert_result($result);
    }

    //UPDATES

    public static function update_session($session_ID, $user_agent, $session_timestamp){
        //$result = self::$wpdb->update('session', array('user_agent' => $user_agent, 'session_timestamp' => $session_timestamp),
        //                  array("session_ID" => $session_ID));

         $sql = "UPDATE session s 
                 SET s.user_agent = %s, s.session_timestamp = %s
                 WHERE s.session_ID = %s";



        $query = self::$wpdb->prepare($sql, array($user_agent, $session_timestamp, $session_ID));
        $result = self::$wpdb->get_results($query, ARRAY_A);

        return self::check_update_result($result);
    }

    public static function update_session_threat_id($session_ID, $threat_ID){
        $old_threat_ID = self::get_threat_by_session($session_ID);

        $sql = "UPDATE session s 
                 SET s.threat_ID = %d
                 WHERE s.session_ID = %s";

        $query = self::$wpdb->prepare($sql, array($threat_ID, $session_ID));
        $result = self::$wpdb->get_results($query, ARRAY_A);

        if($old_threat_ID != $threat_ID){
            self::delete_threat($old_threat_ID);
        }
        

        return self::check_update_result($result);
    }

    public static function update_threat($threat_ID, $threat_score, $threat_status, $breach_flag){
        //$result = self::$wpdb->update('threat', array('threat_score' => $threat_score, 'threat_status' => $threat_status, 'breach_flag' => $breach_flag),
        //                    array("threat_ID" => $threat_ID));
        //var_dump(array($threat_score));

        $sql = "UPDATE threat t
                SET t.threat_score = %d, t.threat_status = %s, t.breach_flag = %d
                WHERE t.threat_ID = %d";

        $query = self::$wpdb->prepare($sql, array($threat_score, $threat_status, $breach_flag, $threat_ID));
        $result = self::$wpdb->get_results($query, ARRAY_A);
        //var_dump($query);

        return self::check_update_result($result);
    }

    public static function update_cookie_value($session_ID, $cookie_ID, $cookie_name, $cookie_value){
        $sql = "UPDATE cookie c
                SET c.cookie_value = %s
                FROM cookie c, session_cookie sc
                WHERE sc.session_ID = %s AND sc.cookie_ID = %d AND c.cookie_name = %s AND sc.cookie_ID = c.cookie_ID";

        $query = self::$wpdb->prepare($sql, array($cookie_value, $session_ID, $cookie_ID, $cookie_name));
        $result = self::$wpdb->get_results($query, ARRAY_A);

        return self::check_update_result($result);
    }

    //DELETES

    public static function delete_ip_address($ip_value){
        $result = self::$wpdb->delete('ip_address', array('ip_value' => $ip_value));

        return self::check_update_result($result);
    }

    public static function delete_session_ip_by_ip_ID($ip_ID){
        $result = self::$wpdb->delete('session_ip', array('ip_ID' => $ip_ID));

        return self::check_update_result($result);
    }

    public static function delete_session_ip_by_session_ID($session_ID){
        $result = self::$wpdb->delete('session_ip', array('session_ID' => $session_ID));

        return self::check_update_result($result);
    }


    public static function delete_session_user_by_session_ID($session_ID){
        $result = self::$wpdb->delete('session_user', array('session_ID' => $session_ID));

        return self::check_update_result($result);
    }
    
    public static function delete_session_user_by_user_ID($user_ID){
        $result = self::$wpdb->delete('session_user', array('user_ID' => $user_ID));

        return self::check_update_result($result);
    }


    public static function delete_cookie($cookie_name, $cookie_value){
        $result = self::$wpdb->delete('cookie', array('cookie_name' => $cookie_name, 'cookie_value' => $cookie_value));

        return self::check_update_result($result);
    }

    public static function delete_session_cookie_by_cookie_ID($cookie_ID){
        $result = self::$wpdb->delete('session_cookie', array('cookie_ID' => $cookie_ID));

        return self::check_update_result($result);
    }

    public static function delete_session_cookie_by_session_ID($session_ID){
        $result = self::$wpdb->delete('session_cookie', array('session_ID' => $session_ID));

        return self::check_update_result($result);
    }

    public static function delete_session($session_ID){
        $result = self::$wpdb->delete('session', array('session_ID' => $session_ID));

        return self::check_update_result($result);
    }

    public static function delete_threat($threat_ID){
        $result = self::$wpdb->delete('threat', array('threat_ID' => $threat_ID));

        return self::check_update_result($result);
    }



    //UTILITY CHECKS
    private static function check_search_result($result){
        return count($result) > 0;
    }

    private static function check_select_result($result){
        return count($result) > 0 ? $result : null;
    }

    private static function check_insert_result($result){
        return $result > 0 ? self::$wpdb->insert_id : null;
    }

    private static function check_update_result($result){
        return $result > 0 ? $result : null;
    }

}