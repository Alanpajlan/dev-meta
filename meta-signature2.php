return [
  // RCE
  ["pattern" => "/eval\\s*\\(\\s*base64_decode\\s*\\(.*\\)\\s*\\)/i", "risk" => "high", "label" => "eval(base64_decode(...))"],
  ["pattern" => "/(exec|passthru|shell_exec|system)\\s*\\(\\s*\\\$_(POST|GET|REQUEST)/i", "risk" => "high", "label" => "RCE via user input"],
  ["pattern" => "/include\\s*\\(\\s*\\\$_(POST|GET|REQUEST)/i", "risk" => "high", "label" => "include via user input"],

  // Backdoor login
  ["pattern" => "/wp_set_auth_cookie\\s*\\(/i", "risk" => "high", "label" => "Force login backdoor"],
  ["pattern" => "/\\\$_SESSION\\s*\\[\\s*['\"]login['\"]\\s*\\]\\s*===?\\s*true/i", "risk" => "medium", "label" => "session login true check"],

  // Obfuscated payload
  ["pattern" => "/\\\$[a-zA-Z0-9_]+\\s*=\\s*['\"]eJw[0-9A-Za-z+\/=]{100,}['\"]/i", "risk" => "high", "label" => "obfuscated gzip+base64"],
  ["pattern" => "/eval\\s*\\(\\s*\\\$[a-z_]{3,}\\s*\\)/i", "risk" => "high", "label" => "eval variable payload"],

  // Stealth techniques
  ["pattern" => "/<FilesMatch\\s+['\"]\\^\\(.*wp-log1n\\.php.*\\)\\\$['\"]>/i", "risk" => "high", "label" => ".htaccess allow stealth login"],
  ["pattern" => "/goto\\s+[a-zA-Z0-9_]+\\s*;/i", "risk" => "medium", "label" => "use of goto (control obfuscation)"],
];