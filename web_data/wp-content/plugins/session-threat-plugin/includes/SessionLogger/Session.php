<?php

namespace Inc\SessionLogger;


class Session {
    private $ip_addresses;
    private $user_agent;
    private $last_request_timestamp;
    private $threat_score;
    private $threat_status;
    private $breach_flag;
    private $cookie;
    private $email;
    private $wp_session_cookie;
    private $session_timestamp;
    private $page_loads_count;
    
    public function __construct($ip_address, $user_agent, $last_request_timestamp, $threat_score, $breach_flag, $cookie, $email, $session_timestamp, $wp_session_cookie){
        $this->ip_addresses = array($ip_address);
        $this->user_agent = $user_agent;
        $this->last_request_timestamp = $last_request_timestamp;
        $this->page_loads_count = 0;

        //threat indicators
        $this->threat_status = "safe_user";
        $this->threat_score = $threat_score;
        $this->breach_flag = $breach_flag;

        $this->wp_session_cookie = $wp_session_cookie;
        $this->email = $email;
        $this->session_timestamp = $session_timestamp;
        
        

        $this->cookie = $cookie;
        
    }

    public function log_user_session(){
        return $this->check_session_existance();
    }

    private function build_json_session(){
        $ips = array();
        $session_ids = array();

        foreach($this->ip_addresses as $ip){
            array_push($ips, $ip);
        }
        
        if($this->wp_session_cookie != null){
            foreach($this->wp_session_cookie as $session_id){
                array_push($session_ids, $session_id);
            }

        }
        else{
            $session_ids = null;
        }

        return array("ip_addresses" => $ips,
        "user_agent" => $this->user_agent,
         "session_timestamp" => $this->session_timestamp,
        "last_request_timestamp" => $this->last_request_timestamp,
        "email" => $this->email, "cookie" => $this->cookie,
        "threat_status" => $this->threat_status,
        "threat_score" => $this->threat_score,
        "breach_flag" => $this->breach_flag,
        "page_loads_count" => $this->page_loads_count,
        "wp_session_cookie" => $session_ids,
        "timestamp" => date("c")
      );
    }

    private function check_session_existance(){
        $sessions_json_data = file_get_contents(PLUGIN_PATH . "includes/SessionLogger/sessions.json");
        $sessions_data = json_decode($sessions_json_data, true);
        $session_data = $this->build_json_session();
        $updated_sessions = array();

        if(empty($sessions_data)){
            $sessions_data = array($session_data);
        }
        else{
            if($this->email != null){
                $result_check = $this->update_data_by_email($sessions_data);
                if($result_check["found"]){
                    $sessions_data = $result_check["data"];
                }
            }
            
            
            $result = $this->delete_redundant_session($sessions_data, $session_data);
            $sessions_data = $result["sessions"];

            //Account relativo a una delle sessioni precedenti (anche dopo logout)
            if(count($result["updated"]) > 0){
                array_push($updated_sessions, $result["updated"]);
            }
        }

        //Nuovo account non relativo a nessuna delle altre sessioni
        if(count($updated_sessions) <= 0){
            array_push($updated_sessions, array($session_data));
        }


        $session_json_data = json_encode($sessions_data, JSON_FORCE_OBJECT);
        file_put_contents(PLUGIN_PATH . "includes/SessionLogger/sessions.json", $session_json_data);

        return array_values($updated_sessions);
    }

    private function update_data_by_email($sessions_data){
        $found = false;
        $updated_sessions = array();

        foreach($sessions_data as $session => $data){
            if($data["email"] == $this->email){
                $found = true;
                $ips = $data["ip_addresses"];
                $session_ids = $data["wp_session_cookie"];


                $merged_ips = array_merge($ips, $this->ip_addresses);
                $merged_ids = array_unique(array_merge($session_ids, $this->wp_session_cookie));

                //<= or < ?, now seems working
                if(count($merged_ips) <= count($merged_ids)){
                    $sessions_data[$session]["ip_addresses"] = $merged_ips;
                }

                
                $sessions_data[$session]["wp_session_cookie"] = $merged_ids;
                
                $sessions_data[$session]["user_agent"] = $this->user_agent;
                $sessions_data[$session]["session_timestamp"] = $this->session_timestamp;
                $sessions_data[$session]["last_request_timestamp"] = $this->last_request_timestamp;
                $sessions_data[$session]["cookie"] = $this->cookie;


                $threat_data = $sessions_data;
                $sessions_data[$session]["threat_score"] = 0;

                foreach($threat_data as $threat => $threat_data){
                    if($threat_data["cookie"] == $this->cookie){
                        $sessions_data[$session]["threat_score"] += $threat_data["threat_score"];
                    }
                }

                array_push($updated_sessions, $sessions_data[$session]);
                
            }
        }

        return array("found" => $found, "data" => $sessions_data, "updated" => $updated_sessions);
    }

    private function delete_redundant_session($sessions_data, $session_data){
        $threat_updated = false;
        $updated_sessions = array();

        foreach($sessions_data as $session => $data){
            //Aggrega le informazioni relative al livello di minaccia a seconda dell'utente
            if($data["cookie"] == $this->cookie && $data["last_request_timestamp"] <= $this->last_request_timestamp && !$threat_updated){
                $session_data["threat_score"] = intval($sessions_data[$session]["threat_score"] + $this->threat_score);
                $session_data["threat_status"] = $this->compute_threat_status($session_data["threat_score"], $this->breach_flag);
                $session_data["breach_flag"] = $this->breach_flag;

                if(is_null($data["wp_session_cookie"]) && count($this->wp_session_cookie) > 0){
                    $session_data["wp_session_cookie"] = $this->wp_session_cookie;
                }

                $session_data["page_loads_count"] = $sessions_data[$session]["page_loads_count"] + 1;

                $threat_updated = true;
            }

            //Rimuove un php session id dalla lista di quelli presenti in un account nel caso sia stato effettuato un log out
            if($data["cookie"] == $this->cookie && $data["last_request_timestamp"] <= $this->last_request_timestamp && is_null($this->email)){  
                if(count($this->wp_session_cookie) == 1 && isset($data["wp_session_cookie"]) && in_array($this->wp_session_cookie[0], $data["wp_session_cookie"])){
                    unset($sessions_data[$session]["wp_session_cookie"][array_search($this->wp_session_cookie[0], $sessions_data[$session]["wp_session_cookie"])]);
                }
            }

            //Controlla che la sessione non venga duplicata con le stesse informazioni
            if($data["cookie"] == $this->cookie  && ((is_null($data["email"]) && is_null($this->email)) || ($data["email"] == $this->email))){
                if(!is_null($this->email)){
                    $session_ids = $data["wp_session_cookie"];
                    $merged_ids = array_unique(array_merge($session_ids, $this->wp_session_cookie));

                    $session_data["wp_session_cookie"] = $merged_ids;
                    $session_data["ip_addresses"] = $sessions_data[$session]["ip_addresses"];
                }

                unset($sessions_data[$session]);

            }


            //Elimina un indirizzo dalla lista di ip quando un utente effettua il logout, se la lista è vuota viene rimossa la sessione
            if($data["cookie"] == $this->cookie && $data["last_request_timestamp"] <= $this->last_request_timestamp && ((is_null($data["email"]) && !is_null($this->email)) || (!is_null($data["email"]) && is_null($this->email)))){

                if(count($sessions_data[$session]["ip_addresses"]) > 1){
                    $prev_ip = null;

                    foreach($sessions_data[$session]["ip_addresses"] as $ip_s){
                        if($prev_ip == $ip_s){
                            continue;
                        }
                        foreach($this->ip_addresses as $ip_u){
                            if($ip_s == $ip_u){
                                unset($sessions_data[$session]["ip_addresses"][array_search($ip_s, $sessions_data[$session]["ip_addresses"])]); 
                                
                                break;
                            }
                        }

                        $prev_ip = $ip_s;
                    }

                    $sessions_data[$session]["cookie"] = null;
                    
                    //Aggiorno la sessione da cui un utente ha effettuato il logout ma che è ancora utilizzata da almeno un altro utente
                    array_push($updated_sessions, $sessions_data[$session]);
                }
                else{
                    //Rimuovo una sessione legata ad un account con più nessun utente loggato
                    unset($sessions_data[$session]); 
                }
            }
        }
        
        //Aggiungo i dati della sessione attuale (dopo logout o aggiornamenti vari)
        array_push($updated_sessions, $session_data);
        array_push($sessions_data, $session_data);

        return array("sessions" => array_values($sessions_data), "updated" => array_values($updated_sessions));
    }

    public static function compute_threat_status($threat_score, $breach_flag){
        if($breach_flag){
            return "evil_user";
        }
        else{
            if($threat_score >= 0 && $threat_score <= 49){
                return "safe_user";
            }
            else if($threat_score >= 50 && $threat_score <= 99){
                return "warning_user";
            }
            else if($threat_score >= 100){
                return "dangerous_user";
            }
        }
    }
}



?>