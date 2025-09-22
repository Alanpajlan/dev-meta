<?php
return [
  ["pattern" => "/eval\\s*\\(\\s*\\\$[a-z_]/i", "risk" => "high", "label" => "eval(\$var)"],
  ["pattern" => "/eval\\s*\\(\\s*base64_decode\\s*\\(/i", "risk" => "high", "label" => "eval(base64_decode)"],
  ["pattern" => "/eval\\s*\\(\\s*gzinflate\\s*\\(/i", "risk" => "high", "label" => "eval(gzinflate)"],
  ["pattern" => "/assert\\s*\\(\\s*\\\$_(POST|GET|REQUEST|COOKIE|SERVER)/i", "risk" => "high", "label" => "assert(\$_POST)"],
  ["pattern" => "/preg_replace\\s*\\(.*['\"]\\s*\\/e\\s*['\"].*/i", "risk" => "high", "label" => "preg_replace /e"],
  ["pattern" => "/include\\s*\\(\\s*\\\$_(POST|GET|REQUEST)/i", "risk" => "high", "label" => "include(\$_POST)"],
  ["pattern" => "/include\\s*\\(\\s*['\"]php:\\/\\/input['\"]/i", "risk" => "high", "label" => "include php://input"],
  ["pattern" => "/(exec|shell_exec|passthru|system)\\s*\\(\\s*\\\$_(POST|GET|REQUEST)/i", "risk" => "high", "label" => "RCE via \$_POST"],
  ["pattern" => "/popen\\s*\\(\\s*\\\$_(POST|GET|REQUEST)/i", "risk" => "high", "label" => "popen(\$_POST)"],
  ["pattern" => "/proc_open\\s*\\(\\s*\\\$_(POST|GET|REQUEST)/i", "risk" => "high", "label" => "proc_open(\$_POST)"],
  ["pattern" => "/@?eval\\s*\\(\\s*base64_decode\\s*\\(\\s*base64_decode\\s*\\(/i", "risk" => "high", "label" => "eval double base64"],
  ["pattern" => "/base64_decode\\s*\\(\\s*['\"]\\\\x[0-9a-f]{2}/i", "risk" => "high", "label" => "base64_decode on hex encoded string"],
  ["pattern" => "/eval\\s*\\(\\s*base64_decode\\s*\\(\\s*base64_decode\\s*\\(\\s*['\"]eJw/i", "risk" => "high", "label" => "eval(base64(base64('eJw...'))"],
  ["pattern" => "/eval\\s*\\(\\s*base64_decode\\s*\\(\\s*base64_decode\\s*\\(\\s*\\\$[A-Z_]+\\s*\\)\\s*\\)\\s*\\)/i", "risk" => "high", "label" => "eval(base64(base64(\$VAR)))"],
  ["pattern" => "/\\\$[a-zA-Z0-9_]+\\s*=\\s*['\"]eJw[0-9A-Za-z+\/=]{100,}['\"]/i", "risk" => "high", "label" => "GZIP base64 encoded payload"],
  ["pattern" => "/null;\\s*\\\$[A-Z_]+\\s*=\\s*['\"]eJw/i", "risk" => "high", "label" => "payload start after null; \$VAR = 'eJw...'"],

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

  ["pattern" => "/chr\\s*\\(\\s*[0-9]{1,3}\\s*\\)/i", "risk" => "low", "label" => "chr()"],
  ["pattern" => "/is_callable\\s*\\(/i", "risk" => "low", "label" => "is_callable"],
  ["pattern" => "/function_exists\\s*\\(\\s*['\"]assert['\"]\\s*\\)/i", "risk" => "low", "label" => "check if assert exists"],
  ["pattern" => "/define\\s*\\(\\s*['\"]\\w+['\"]\\s*,\\s*['\"]\\w+['\"]\\s*\\)/i", "risk" => "low", "label" => "suspicious define"],
  ["pattern" => "/ini_set\\s*\\(\\s*['\"](log_errors|display_errors)['\"]\\s*,\\s*['\"]?0['\"]?\\s*\\)/i", "risk" => "low", "label" => "suppress error logging"]
];["pattern" => "/\\\$_SESSION\\s*\\[\\s*['\"]login['\"]\\s*\\]\\s*===?\\s*true/i", "risk" => "medium", "label" => "session login true check"],
["pattern" => "/if\\s*\\(!isset\\s*\\(\\s*\\\$_SESSION\\s*\\[\\s*['\"]login['\"]\\s*\\]\\s*\\)\\)\\s*die\\s*\\(/i", "risk" => "medium", "label" => "session gate then die()"],
["pattern" => "/<title>\\s*bcdr/i", "risk" => "medium", "label" => "HTML title bcdr"],
["pattern" => "/\\\$[a-zA-Z0-9_]+\\s*=\\s*['\"]eJw[0-9A-Za-z+\\/=]{100,}['\"];.*eval\\s*\\(\\s*base64_decode\\s*\\(\\s*base64_decode\\s*\\(\\s*\\\$[a-zA-Z0-9_]+\\s*\\)\\s*\\)\\s*\\)/is", "risk" => "high", "label" => "eval(base64(base64(\$payload))) inline"],
["pattern" => "/\\\$_POST\\[['\"]pwdyt['\"]\\].*hash\\s*\\(.*hash.*\\)\\s*==\\s*\\\$auth/is", "risk" => "medium", "label" => "pwdyt double hash login check"]
[
  ["pattern" => "/\\\$[a-zA-Z_]{3,}\\s*=\\s*['\\\"](?:eJw|\\\x[0-9a-fA-F]{2}){100,}/i", "risk" => "high", "label" => "Obfuscated payload string (hex or gzip-base64)"],
  ["pattern" => "/eval\\s*\\(\\s*\\\$[a-zA-Z_]{3,}\\s*\\)/i", "risk" => "high", "label" => "eval(\$payload) from variable"],
  ["pattern" => "/\\\$[A-Z][a-z]{3}\\s*=\\s*['\\\"]/i", "risk" => "medium", "label" => "Suspicious capitalized variable (possible payload)"],
  ["pattern" => "/chr\\s*\\(\\s*ord\\s*\\(.*\\)\\s*\\^\\s*.*\\)/i", "risk" => "high", "label" => "XOR decode + eval() obfuscation"]
][
  ["pattern" => "/file_get_contents\\s*\\(\\s*base64_decode\\s*\\(/i", "risk" => "high", "label" => "Remote include via base64-decoded URL"],
  ["pattern" => "/eval\\s*\\(\\s*['\\\"]\\?>['\\\"]\\s*\\.\\s*\\\$[a-z_]+\\s*\\)/i", "risk" => "high", "label" => "eval('?>' . \$payload)"],
  ["pattern" => "/base64_decode\\s*\\(\\s*['\\\"]aHR0cHM6/i", "risk" => "medium", "label" => "Base64-encoded URL (starts with https://)"]
][
  ["pattern" => "/eval\\s*\\(\\s*base64_decode\\s*\\(\\s*['\"][a-zA-Z0-9+\\/=]{100,}['\"]\\s*\\)\\s*\\)/i", "risk" => "high", "label" => "eval(base64_decode('massive_payload'))"],
  ["pattern" => "/goto\\s+[a-zA-Z0-9_]+\\s*;/i", "risk" => "high", "label" => "goto used in code (obfuscation or control flow hiding)"],
  ["pattern" => "/WP_User_Query\\s*\\(/i", "risk" => "medium", "label" => "WP_User_Query to hijack admin session"],
  ["pattern" => "/wp_set_auth_cookie\\s*\\(/i", "risk" => "medium", "label" => "Forced WordPress login via auth_cookie"],
  ["pattern" => "/wp_redirect\\s*\\(/i", "risk" => "medium", "label" => "Forced redirect, possibly after auth injection"],
  ["pattern" => "/include\\s*\\(\\s*['\"]\\\\x[0-9a-f]{2}/i", "risk" => "medium", "label" => "Include path with hex escape sequence"]
][
  ["pattern" => "/<FilesMatch\\s+['\"]\\.\(py\|exe\|phtml\|php.*suspected\)\\\$['\"]>/i", "risk" => "high", "label" => ".htaccess: Deny access to .php/phtml/py/suspected"],
  ["pattern" => "/<FilesMatch\\s+['\"]\\^\\(.*wp-log1n\\.php.*\\)\\\$['\"]>/i", "risk" => "high", "label" => ".htaccess: Allow access to suspicious PHP files"],
  ["pattern" => "/Order\\s+allow,deny\\s+Allow\\s+from\\s+all/i", "risk" => "medium", "label" => ".htaccess: Allow override for specific backdoor files"]
]