<?php
/**
 * @package           SessionThreatPlugin
*/

namespace Inc\Database;

use \Inc\Database\DBClient;
use \Inc\SessionLogger\Session;

//IF USER LOGS OUT, GENERATE NEW THREAT_ID FOR THE USER BUT MAINTAIN SCORE PERSISTENCY
class DBProcedures {

    //ignore session_id cookie null on first access

    public static function choose_action($data){
        if(!DBClient::search_session_id($data["session_id"])){
            echo "session id non trovato ";

            if(is_null($data["user_id"])){
                //create new session
                echo "user id non trovato, creo nuova sessione ";
                self::create_session($data);

            }
            else{
                echo "user id trovato ";
                //recover session_id associated with user_id
                if(DBClient::compare_session_id_by_user_id($data["session_id"], $data["user_id"])){
                    echo "session id e user id presenti in session user ";
                    if(self::check_session_consistency($data)){
                        echo "record consistenti, aggiorno ";
                        self::update_session($data);
                    }
                    else{
                        echo "record inconsistenti, creata nuova sessione ";
                    }
                }
                else{
                    //user_id not associated with session, create new session
                    echo "session id e user id non presenti in session user ";
                    self::create_session($data);
                    self::update_threat($data);
                }
            }
        }
        else{
            echo "ho trovato il session id, aggiorno ";
            //session id trovato, procedo all'update

            /*if(!is_null($data["user_id"])){
                //aggiornamenti specifici su tabella session_user
            }
            else{
                self::update_session($data);
            }*/
            self::update_session($data);

            $result = DBClient::get_threat_data_by_id(58);
            //var_dump($result);
        }
    }

    //WORKS
    private static function create_session($data){
        DBClient::start_transaction();
        DBClient::disable_foreign_checks();

	//var_dump($data);
	//$threat_status = Session::compute_threat_status($data["threat_score"], $data{"breach_flag"]);
        $threat_ID = DBClient::insert_threat($data["threat_score"], $data["threat_status"], $data["breach_flag"]);


        if(is_null($threat_ID)){
            DBClient::rollback_transaction();
            return;
        }

        
        $session_index = DBClient::insert_session($data["session_id"], $threat_ID, $data["user_agent"], $data["session_timestamp"]);
        

        if(is_null($session_index)){
            echo "rollback 1";
            DBClient::rollback_transaction();
            return;
        }


        $cookie_insertion_result = self::multiple_cookie_insertion($data["cookie"], $data["session_id"]);

        if(is_null($cookie_insertion_result)){
            echo "rollback 2";
            DBClient::rollback_transaction();
            return;
        }

        $bind_session_user_result = self::bind_session_and_user($data["session_id"], $data["user_id"]);

        if(is_null($bind_session_user_result)){
            echo "rollback 3";
            DBClient::rollback_transaction();
            return;
        }


        $ip_ID = DBClient::insert_ip_address($data["ip_address"]);

        if(is_null($ip_ID)){
            echo "rollback 4";
            DBClient::rollback_transaction();
            return;
        }

        $session_ip_result = DBCLient::insert_session_ip($data["session_id"], $ip_ID);
        
        if(is_null($session_ip_result)){
            echo "rollback 5";
            DBClient::rollback_transaction();
            return;
        }


        
        DBClient::commit_transaction();
        DBClient::enable_foreign_checks();
    }

    private static function update_session($data){
        DBClient::start_transaction();
        DBClient::disable_foreign_checks();

        $session_update_result = DBClient::update_session($data["session_id"], $data["user_agent"], $data["session_timestamp"]);

        if(is_null($session_update_result)){
            echo "rollback update session";
            DBClient::rollback_transaction();
            return;
        }

        $threat_ID = DBClient::get_threat_by_session($data["session_id"]);

        if(is_null($threat_ID)){
            echo "rollback get threat";
            DBClient::rollback_transaction();
            return;
        }

        //$threat_update_result = DBClient::update_threat($threat_ID, $data["threat_score"], $data["threat_status"], $data["breach_flag"]);
        $threat_update_result = self::compute_score($threat_ID, $data["threat_score"], $data["breach_flag"]);

        if(is_null($threat_update_result)){
            echo "rollback update threat";
            DBClient::rollback_transaction();
            return;
        }
        //
        //$result = DBClient::get_threat_data_by_id($threat_ID);
        //var_dump($result);
        //

        if(is_null(self::add_new_ip_address($data["session_id"], $data["ip_address"]))){
            echo "rollback add new ip";
            DBClient::rollback_transaction();
            return;
        }

        if(is_null(self::add_new_cookies($data["cookie"], $data["session_id"]))){
            echo "rollback update cookie";
            DBClient::rollback_transaction();
            return;
        }

        if(is_null(self::update_session_user($data))){
            echo "rollback update userr";
            DBClient::rollback_transaction();
            return;
        }

        DBClient::commit_transaction();
        DBClient::enable_foreign_checks();

    }

    private static function check_session_consistency($data){
        if(is_null(DBClient::search_session_id($data["session_id"]))){
            self::create_session($data); 
            return false;   
        }

        return true;
    }

    private static function multiple_cookie_insertion($cookie_array, $session_ID){

        foreach($cookie_array as $name => $value){
            
            $cookie_ID = DBClient::insert_cookie($name, $value);

            if(is_null($cookie_ID)){
                return null;
            }

            $session_cookie_index = DBClient::insert_session_cookie($cookie_ID, $session_ID);

            if(is_null($session_cookie_index)){
                return null;
            }
        }

        return 1;
    }

    private static function add_new_ip_address($session_ID, $ip_value){
        //if count = 0 but ip already associated with another session, use that instead of inserting new one
        $ip_count = DBClient::get_matching_ip_count($ip_value, $session_ID);
        if($ip_count == 0){
            //new ip
            $ip_ID = DBClient::insert_ip_address($ip_value);

            if(is_null($ip_ID)){
                return null;
            }

            $session_ip_result = DBClient::insert_session_ip($session_ID, $ip_ID);

            if(is_null($session_ip_result)){
                return null;
            }
        }

        return 1;
    }

    private static function add_new_cookies($cookies, $session_ID){
        self::remove_unmatched_cookies($cookies, $session_ID);

        foreach($cookies as $key => $value){
            $cookie_count = DBClient::get_cookie_count_by_session($session_ID, $key, $value);

            if($cookie_count == 0){
                $cookie_ID = DBClient::get_cookie_id_by_name_and_session($session_ID, $key);

                if(!is_null($cookie_ID)){
                    if(is_null(DBClient::update_cookie_value($session_ID, $cookie_ID, $key, $value))){
                        return null;
                    }
                }
                else{
                    $cookie_ID = DBClient::insert_cookie($key, $value);

                    if(is_null($cookie_ID)){
                        return null;
                    }

                    DBClient::insert_session_cookie($cookie_ID, $session_ID);
                }
            }
        }

        return 1;
    }

    private static function update_session_user($data){
        if((is_null($data["user_id"])) && (!is_null(DBClient::get_user_id_by_session_id($data["session_id"])))){
            //cancello entry session_user
            echo "log out, elimina la entry in session user";

            //creazione di un nuovo threat id per l'utente che effettua il log out
            $threat_ID = DBClient::get_threat_by_session($data["session_id"]);

            if(is_null($threat_ID)){
                return null;
            }
            if(is_null(DBClient::update_session_threat_id($data["session_id"], null))){
                return null;
            }

            DBClient::delete_session_user_by_session_ID($data["session_id"]);

            return 1;
        }
        else if((!is_null($data["user_id"])) && (is_null(DBClient::get_user_id_by_session_id($data["session_id"])))){
            //inserisco entry session_user
            echo "log in, inserisco entry in session user";
            DBClient::insert_session_user($data["session_id"], $data["user_id"]);

            if(is_null(self::update_threat($data))){
                return null;
            }

            

            return 1;
        }
        else{
            return 1;
        }
    }

    private static function update_threat($data){
        $session_ids = DBClient::get_session_id_by_user_id($data["user_id"]);


        for($i=0; $i<=count($session_ids); $i++){
            if($session_ids[$i]["session_ID"] == $data["session_id"]){
                unset($session_ids[$i]);
            }
            else{
                $other_user_session_id = $session_ids[$i]["session_ID"];
            }
        }

        if(!empty($session_ids)){
            echo "c'è un utente già loggato con l'account ";
            $threat_ID = DBClient::get_threat_by_session($other_user_session_id);

            if(is_null($threat_ID)){
                return null;
            }

            //update threat_id in session
            if(is_null(self::compute_score($threat_ID, $data["threat_score"], $data["breach_flag"]))){
                return null;
            }
            
            if(is_null(DBClient::update_session_threat_id($data["session_id"], $threat_ID))){
                return null;
            }

        }

        return 1;
    }

    //Score is updated twice in db but methods are called only once: Happens because browser is maing 2 requests, one is for favicon
    private static function compute_score($threat_ID, $request_threat_score, $request_breach_flag){
            $old_threat_data = DBClient::get_threat_data_by_id($threat_ID);

            
            $new_threat_score = $old_threat_data[0]["threat_score"] + $request_threat_score;
            $new_breach_flag = $old_threat_data[0]["breach_flag"] || $request_breach_flag;
            $new_threat_status = Session::compute_threat_status($new_threat_score, $new_breach_flag);

            //var_dump(array($old_threat_data[0]["threat_score"], $request_threat_score));
            //var_dump(array($new_threat_score));

            return DBClient::update_threat($threat_ID, $new_threat_score, $new_threat_status, $new_breach_flag);

            
    }

    //removes db cookies not matched with any of a specific user
    private static function remove_unmatched_cookies($cookies, $session_ID){
        $db_session_cookies = DBClient::get_all_cookies_by_session($session_ID);

        foreach($db_session_cookies as $db_cookie){
            $found = false;

            foreach($cookies as $cookie_key => $cookie_value){
                if($db_cookie["cookie_name"] == $cookie_key){
                    $found = true;
                }
            }

            if(!$found){
                echo "deleting";
                DBClient::delete_session_cookie_by_cookie_ID($db_cookie["cookie_ID"]);
                DBClient::delete_cookie($db_cookie["cookie_name"], $db_cookie["cookie_value"]);
            }
        }
    }

    private static function bind_session_and_user($session_ID, $user_ID){
        if(!is_null($user_ID)){
            $session_user_index = DBClient::insert_session_user($session_ID, $user_ID);

            if(is_null($session_user_index)){
                return null;
            }
        }

        return 1;
    }
}




?>
