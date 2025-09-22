<?php
header('Content-Type: application/json');

echo json_encode([
  // ==== EVAL + OBFUSCATED DECODE ====
  ["pattern" => "/@?eval\\s*\\(\\s*(base64|gzinflate|gzuncompress|str_rot13|rawurldecode|urldecode)/i", "risk" => "high", "label" => "eval(decode function)"],
  ["pattern" => "/eval\\s*\\(\\s*(\\\$[a-zA-Z_][a-zA-Z0-9_]*)\\s*\\)/i", "risk" => "high", "label" => "eval(\$var)"],
  ["pattern" => "/eval\\s*\\(.*base64_decode.*base64_decode/i", "risk" => "high", "label" => "eval(base64(base64(...)))"],
  ["pattern" => "/eval\\s*\\(\\s*base64_decode\\s*\\(\\s*['\"]\\\\x[0-9a-f]{2}/i", "risk" => "high", "label" => "eval(base64(hex encoded string))"],
  
  // ==== CHAINED PAYLOAD DECODE ====
  ["pattern" => "/(base64_decode|gzinflate|gzuncompress|str_rot13|urldecode|rawurldecode)\\s*\\(\\s*\\1/i", "risk" => "high", "label" => "chained decode (recursive function)"],
  ["pattern" => "/(str_rot13|base64_decode|gzinflate|gzuncompress|urldecode|rawurldecode).*\\(.*['\"][A-Za-z0-9+\/=]{200,}['\"]\\)/i", "risk" => "high", "label" => "decode on long encoded string"],

  // ==== HEX ENCODED STRINGS ====
  ["pattern" => "/['\"]\\\\x[0-9a-f]{2}(\\\\x[0-9a-f]{2}){5,}['\"]/i", "risk" => "high", "label" => "hex encoded string (obfuscation)"],

  // ==== LONG STRINGS ====
  ["pattern" => "/['\"][A-Za-z0-9+\/=]{400,}['\"]/i", "risk" => "medium", "label" => "suspiciously long string"],

  // ==== SESSION GATE BACKDOOR ====
  ["pattern" => "/\\\$_SESSION\\s*\\[\\s*['\"][a-zA-Z0-9_]{5,}['\"]\\s*\\]/i", "risk" => "medium", "label" => "session-based auth check"],
  ["pattern" => "/hash\\s*\\(\\s*['\"]sha(1|256|512)['\"]\\s*,\\s*hash\\s*\\(/i", "risk" => "medium", "label" => "double SHA hash login"],

  // ==== PASSWORD FORM ====
  ["pattern" => "/<form[^>]+method=['\"]post['\"][^>]*>.*type=['\"]password['\"]/is", "risk" => "medium", "label" => "HTML password form"],

  // ==== OB_START ABUSE ====
  ["pattern" => "/ob_start\\s*\\(/i", "risk" => "medium", "label" => "ob_start() output buffer"],

  // ==== DANGEROUS FUNCTION EXEC ====
  ["pattern" => "/(shell_exec|system|passthru|popen|proc_open)\\s*\\(/i", "risk" => "high", "label" => "dangerous execution function"],

  // ==== VARIABLE VARIABLES ====
  ["pattern" => "/\\\$\\{\\\$[a-zA-Z0-9_]+\\}/i", "risk" => "high", "label" => "variable variable (obfuscation)"],

  // ==== GOTO TRICKS ====
  ["pattern" => "/goto\\s+[a-zA-Z0-9_]+/i", "risk" => "medium", "label" => "goto usage (obfuscation)"],

  // ==== NULL + PAYLOAD ====
  ["pattern" => "/null;\\s*\\\$[A-Z_]{4,}\\s*=\\s*['\"]eJw/i", "risk" => "high", "label" => "null; \$VAR = 'eJw...' payload"]
]);