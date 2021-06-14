<?php

class Evaluator {
    private $wordlists_paths;
    private $wordlists;
    private $wordlist_sizes;
    private $breach_flag = false;

    public function __construct($wordlists_paths){
        $this->wordlists_paths = $wordlists_paths;
        $this->wordlists = array();
        $this->wordlist_sizes = array();

        $this->load_wordlists();
    }

    private function load_wordlists(){
        foreach($this->wordlists_paths as $path){
            $filename = pathinfo($path, PATHINFO_FILENAME);
            $wordlist_array = explode("\n", file_get_contents($path));

            foreach($wordlist_array as $word){
                trim($word);
            }

            $this->wordlists[$filename] = array_map("trim", $wordlist_array);
            $this->wordlist_sizes[$filename] = !empty(file_get_contents($path));
        }
    }

    public function analyze_request($request){
        $get_score = 0; 
        $post_score = 0;
        $cookies_score = 0;
        $script_score = 0;
        $honeyuser_score = 0;


        //check empty file
        if($this->wordlist_sizes["blacklist_get_keys"] && $this->wordlist_sizes["blacklist_get_values"] && !empty($request["get_params"]) && count($request["get_params"]) > 0){
           $get_score = $this->analyze_get_params($request["get_params"]);
        }

        if($this->wordlist_sizes["blacklist_post_keys"] && $this->wordlist_sizes["blacklist_post_values"] && !empty($request["post_params"]) && count($request["post_params"]) > 0){
            $post_score = $this->analyze_post_params($request["post_params"]);
        }

        if($this->wordlist_sizes["whitelist_cookie_keys"] && !empty($request["cookies"]) && count($request["cookies"]) > 0){
            $cookies_score = $this->analyze_cookies($request["cookies"]);
        }

        if($this->wordlist_sizes["blacklist_user"] && !empty($request["email"])){
            $honeyuser_score = $this->analyze_honeyuser($request["email"]);
            
            if($honeyuser_score > 0){
                $this->breach_flag = true;
            }
        }

        if($this->wordlist_sizes["file_extensions"] && $this->wordlist_sizes["page_names"]){
            $script_score = $this->analyze_script($request["script_name"]);
        }
        
        
        //return $get_score + $post_score + $cookies_score + $script_score + $honeyuser_score;
        return $cookies_score;
    }

    public function get_breach_flag(){
        return $this->breach_flag;
    }

    private function analyze_get_params($get_params){
        $key_score = count(array_intersect(array_keys($get_params), $this->wordlists["blacklist_get_keys"])) * 10;
        $value_score = count(array_intersect($get_params, $this->wordlists["blacklist_get_values"])) * 10;

        return $key_score + $value_score;

    }

    private function analyze_post_params($post_params){
        $key_score = count(array_intersect(array_keys($post_params), $this->wordlists["blacklist_post_keys"])) * 10;
        $value_score = count(array_intersect($post_params, $this->wordlists["blacklist_post_values"])) * 10;


        return $key_score + $value_score;
    }

    private function analyze_cookies($cookies){
        $over_cookies = array_diff(array_keys($cookies), $this->wordlists["whitelist_cookie_keys"]);
        $score = count($over_cookies);

        //$score -= $this->parse_cookies_wildcards($over_cookies);

        //return $score <= 0 ? 0 : $score * 15;
        return $over_cookies;
    }

    private function analyze_script($script_name){
        $path_array = explode("/", $script_name); 
        $script_filename = $path_array[count($path_array) - 1];

        foreach($this->wordlists["page_names"] as $page){
            if($script_filename == $page){
                return 5;
            }

            foreach($this->wordlists["file_extensions"] as $ext){
                if($script_filename == $page.$ext){
                    return 5;
                }
            }
       }
       
       return 0;
    }

    private function analyze_honeyuser($user){
        foreach($this->wordlists["blacklist_user"] as $blacklisted_account){
            if($user == $blacklisted_account){
                return 100;
            }
        }

        return 0;
    }

    private function parse_cookies_wildcards($over_cookies){
        $wildcards_found = 0;
        foreach($this->wordlists["whitelist_cookie_keys"] as $cookie_key){
            if (substr($cookie_key, -1) == '*') {
                $cookie_length = strlen($cookie_key) - 2;
                foreach($over_cookies as $over_cookie){
                    if(strcmp(substr($over_cookie, $cookie_length), $cookie_key)){
                        $wildcards_found += 1;
                        continue;
                    }
                }
            }
        }

        return $wildcards_found;
    }
}

?>
