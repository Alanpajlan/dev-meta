<?php
return [
  // === HIGH RISK ===
  ["patterns" => ["/eval\\s*\\(/i", "/base64_decode\\s*\\(/i"], "risk" => "high", "label" => "eval + base64_decode"],
  ["patterns" => ["/eval\\s*\\(/i", "/gzinflate\\s*\\(/i"], "risk" => "high", "label" => "eval + gzinflate"],
  ["patterns" => ["/include\\s*\\(/i", "/php:\\/\\/input/i"], "risk" => "high", "label" => "include php://input combo"],
  ["patterns" => ["/(exec|shell_exec|passthru|system)\\s*\\(/i", "/\\\$_(POST|GET|REQUEST)/i"], "risk" => "high", "label" => "RCE function + superglobal"],
  ["patterns" => ["/eval\\s*\\(/i", "/base64_decode\\s*\\(/i", "/eJw/i"], "risk" => "high", "label" => "eval(base64(base64(eJw...))) combo"],
  ["patterns" => ["/\\\$[a-zA-Z0-9_]+\\s*=\\s*['\"]eJw/i", "/gzinflate/i"], "risk" => "high", "label" => "Encoded payload + gzinflate"],

  ["pattern" => "/assert\\s*\\(\\s*\\\$_(POST|GET|REQUEST|COOKIE|SERVER)/i", "risk" => "high", "label" => "assert(\$_POST)"],
  ["pattern" => "/preg_replace\\s*\\(.*['\"]\\s*\\/e\\s*['\"].*/i", "risk" => "high", "label" => "preg_replace /e"],
  ["pattern" => "/popen\\s*\\(\\s*\\\$_(POST|GET|REQUEST)/i", "risk" => "high", "label" => "popen(\$_POST)"],
  ["pattern" => "/proc_open\\s*\\(\\s*\\\$_(POST|GET|REQUEST)/i", "risk" => "high", "label" => "proc_open(\$_POST)"],
  ["pattern" => "/@?eval\\s*\\(\\s*base64_decode\\s*\\(\\s*base64_decode\\s*\\(/i", "risk" => "high", "label" => "eval double base64"],
  ["pattern" => "/base64_decode\\s*\\(\\s*['\"]\\\\x[0-9a-f]{2}/i", "risk" => "high", "label" => "base64_decode on hex encoded string"],
  ["pattern" => "/eval\\s*\\(\\s*base64_decode\\s*\\(\\s*base64_decode\\s*\\(\\s*\\\$[A-Z_]+\\s*\\)\\s*\\)\\s*\\)/i", "risk" => "high", "label" => "eval(base64(base64(\$VAR)))"],
  ["pattern" => "/\\\$[a-zA-Z0-9_]+\\s*=\\s*['\"]eJw[0-9A-Za-z+\/=]{100,}['\"]/i", "risk" => "high", "label" => "GZIP base64 encoded payload"],
  ["pattern" => "/null;\\s*\\\$[A-Z_]+\\s*=\\s*['\"]eJw/i", "risk" => "high", "label" => "payload start after null; \$VAR = 'eJw...'"],

  // [PATCHED] eval('?>' . $response)
  ["pattern" => "/eval\\s*\\(\\s*['\"]\\?>['\"]\\s*\\.\\s*\\\$[a-zA-Z0-9_]+\\s*\\)/i", "risk" => "high", "label" => "eval('?>' . \$var)"],

  // [PATCHED] curl_exec + eval combo
  ["patterns" => ["/curl_exec\\s*\\(/i", "/eval\\s*\\(/i"], "risk" => "high", "label" => "curl_exec + eval combo"],

  // [PATCHED] all-in-one stealth loader
  ["patterns" => [
    "/ini_set\\s*\\(\\s*['\"]display_errors['\"]\\s*,\\s*['\"]?0['\"]?\\s*\\)/i",
    "/curl_setopt\\s*\\(.*CURLOPT_URL.*https?:\\/\\//i",
    "/curl_exec\\s*\\(/i",
    "/eval\\s*\\(\\s*['\"]\\?>['\"]\\s*\\.\\s*\\\$[a-zA-Z0-9_]+\\s*\\)/i"
  ], "risk" => "high", "label" => "stealth curl+eval loader"],

  // === MEDIUM RISK ===
  ["pattern" => "/create_function\\s*\\(/i", "risk" => "medium", "label" => "create_function"],
  ["pattern" => "/str_rot13\\s*\\(/i", "risk" => "medium", "label" => "str_rot13"],
  ["pattern" => "/\\\$\\w+\\s*=\\s*str_rot13\\s*\\(/i", "risk" => "medium", "label" => "\$var = str_rot13(...)"],
  ["pattern" => "/base64_decode\\s*\\(/i", "risk" => "medium", "label" => "base64_decode"],
  ["pattern" => "/gzinflate\\s*\\(/i", "risk" => "medium", "label" => "gzinflate"],
  ["pattern" => "/gzuncompress\\s*\\(/i", "risk" => "medium", "label" => "gzuncompress"],
  ["pattern" => "/pack\\s*\\(\\s*['\"]H/i", "risk" => "medium", "label" => "pack(H*)"],
  ["pattern" => "/file_get_contents\\s*\\(\\s*['\"]https?:\\/\\//i", "risk" => "medium", "label" => "remote file_get_contents"],
  ["pattern" => "/curl_setopt\\s*\\(\\s*\\\$[a-z0-9_]+\\s*,\\s*CURLOPT_URL\\s*,\\s*['\"]https?:\\/\\//i", "risk" => "medium", "label" => "curl to remote URL"],
  ["pattern" => "/curl_getinfo\\s*\\(.*CURLINFO_HTTP_CODE.*\\);/i", "risk" => "medium", "label" => "cURL status check"],
  ["pattern" => "/curl_setopt\\s*\\(\\s*\\\$[a-zA-Z0-9_]+\\s*,\\s*CURLOPT_HTTPHEADER/i", "risk" => "medium", "label" => "Custom HTTP headers"],
  ["pattern" => "/\\\$user_agents\\s*=\\s*\\[/i", "risk" => "medium", "label" => "User-Agent randomizer array"],
  ["pattern" => "/\\\$referers\\s*=\\s*\\[/i", "risk" => "medium", "label" => "Referer randomizer array"],
  ["pattern" => "/parse_str\\s*\\(\\s*\\\$_(GET|POST|REQUEST)/i", "risk" => "medium", "label" => "parse_str(\$_POST)"],
  ["pattern" => "/strrev\\s*\\(/i", "risk" => "medium", "label" => "strrev() obfuscation"],
  ["pattern" => "/ob_start\\s*\\(.*\\)/i", "risk" => "medium", "label" => "ob_start() used"],
  ["pattern" => "/hash\\s*\\(\\s*['\"]sha256['\"]\\s*,\\s*hash\\s*\\(\\s*['\"]sha256['\"]\\s*,/i", "risk" => "medium", "label" => "double SHA256 hash login"],
  ["pattern" => "/\\\$_SESSION\\s*\\[\\s*['\"]secretyt['\"]\\s*\\]/i", "risk" => "medium", "label" => "session 'secretyt' backdoor check"],
  ["pattern" => "/if\\s*\\(!\\s*\\\$_SESSION\\s*\\[.*\\]\\s*\\).*die\\s*\\(/i", "risk" => "medium", "label" => "session gate with die()"],
  ["pattern" => "/<form[^>]*method=['\"]post['\"][^>]*>.*<input[^>]*type=['\"]password['\"][^>]*>/is", "risk" => "medium", "label" => "HTML password form"],
  ["pattern" => "/['\"]pwdyt['\"]/", "risk" => "medium", "label" => "pwdyt field name"],

  // [PATCHED] User-Agent spoofing via rand()
  ["pattern" => "/Macintosh;.*rand\\s*\\(/i", "risk" => "medium", "label" => "Macintosh User-Agent spoof via rand()"],
  ["pattern" => "/iPhone;.*rand\\s*\\(/i", "risk" => "medium", "label" => "iPhone User-Agent spoof via rand()"],

  // === LOW RISK ===
  ["pattern" => "/chr\\s*\\(\\s*[0-9]{1,3}\\s*\\)/i", "risk" => "low", "label" => "chr()"],
  ["pattern" => "/is_callable\\s*\\(/i", "risk" => "low", "label" => "is_callable"],
  ["pattern" => "/function_exists\\s*\\(\\s*['\"]assert['\"]\\s*\\)/i", "risk" => "low", "label" => "check if assert exists"],
  ["pattern" => "/define\\s*\\(\\s*['\"]\\w+['\"]\\s*,\\s*['\"]\\w+['\"]\\s*\\)/i", "risk" => "low", "label" => "suspicious define"],
  ["pattern" => "/ini_set\\s*\\(\\s*['\"](log_errors|display_errors)['\"]\\s*,\\s*['\"]?0['\"]?\\s*\\)/i", "risk" => "low", "label" => "suppress error logging"]
];