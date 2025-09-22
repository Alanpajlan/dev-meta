<?php
header('Content-Type: application/json');

echo json_encode([
  ["pattern" => "/eval\\s*\\(\\s*\\\$[a-z_]/i", "risk" => "high", "label" => "eval(\$var)"],
  ["pattern" => "/eval\\s*\\(\\s*base64_decode\\s*\\(/i", "risk" => "high", "label" => "eval(base64_decode)"],
  ["pattern" => "/eval\\s*\\(\\s*gzinflate\\s*\\(/i", "risk" => "high", "label" => "eval(gzinflate)"],
  ["pattern" => "/assert\\s*\\(\\s*\\\$_(POST|GET|REQUEST)/i", "risk" => "high", "label" => "assert(\$_POST)"],
  ["pattern" => "/preg_replace\\s*\\(.*\\/e.*/i", "risk" => "high", "label" => "preg_replace /e"],
  ["pattern" => "/create_function\\s*\\(/i", "risk" => "medium", "label" => "create_function"],
  ["pattern" => "/str_rot13\\s*\\(/i", "risk" => "medium", "label" => "str_rot13"],
  ["pattern" => "/\\\$\\w+\\s*=\\s*str_rot13\\s*\\(/i", "risk" => "medium", "label" => "\$var = str_rot13(...)"],
  ["pattern" => "/base64_decode\\s*\\(/i", "risk" => "medium", "label" => "base64_decode"],
  ["pattern" => "/gzinflate\\s*\\(/i", "risk" => "medium", "label" => "gzinflate"],
  ["pattern" => "/gzuncompress\\s*\\(/i", "risk" => "medium", "label" => "gzuncompress"],
  ["pattern" => "/pack\\s*\\(\\s*['\"]H/i", "risk" => "medium", "label" => "pack(H*)"],
  ["pattern" => "/chr\\s*\\(\\s*[0-9]{1,3}\\s*\\)/i", "risk" => "low", "label" => "chr()"],
  ["pattern" => "/curl_setopt\\s*\\(.*CURLOPT_URL.*http/i", "risk" => "medium", "label" => "curl to remote URL"],
  ["pattern" => "/file_get_contents\\s*\\(\\s*['\"]https?:\\/\\//i", "risk" => "medium", "label" => "remote file_get_contents"],
  ["pattern" => "/include\\s*\\(\\s*\\\$_(POST|GET|REQUEST)/i", "risk" => "high", "label" => "include(\$_POST)"],
  ["pattern" => "/include\\s*\\(\\s*['\"]php:\\/\\/input['\"]/i", "risk" => "high", "label" => "include php://input"],
  ["pattern" => "/(exec|shell_exec|passthru|system)\\s*\\(\\s*\\\$_(POST|GET|REQUEST)/i", "risk" => "high", "label" => "RCE via \$_POST"],
  ["pattern" => "/popen\\s*\\(\\s*\\\$_(POST|GET|REQUEST)/i", "risk" => "high", "label" => "popen(\$_POST)"],
  ["pattern" => "/proc_open\\s*\\(\\s*\\\$_(POST|GET|REQUEST)/i", "risk" => "high", "label" => "proc_open(\$_POST)"]
]);