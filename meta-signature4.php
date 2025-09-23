<?php
return [

  // === BACKDOOR 1: gx-d3f.pages.dev + base64_decode
  [
    "patterns" => [
      "/base64_decode\s*\(\s*['\"]aHR0cHM6Ly9neC1kM2YucGFnZXMuZGV2/i",
      "/file_get_contents\s*\(/i",
      "/eval\s*\(\s*['\"]\?\>\s*\.\s*\$/i"
    ],
    "risk" => "high",
    "label" => "Backdoor #1: gx-d3f.pages.dev base64 loader"
  ],

  // === BACKDOOR 2: GitHub raw + ?ollehk=1011
  [
    "patterns" => [
      "/\?ollehk=1011/",
      "/onboarding_plugins\s*\(\s*['\"]hello['\"]\s*\)/i",
      "/curl_exec\s*\(/i",
      "/base64_decode\s*\(\s*['\"]aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29t/i",
      "/eval\s*\(/i"
    ],
    "risk" => "high",
    "label" => "Backdoor #2: GitHub loader + GET key"
  ],

  // === BACKDOOR 3: Temp file loader from raw.githubusercontent.com
  [
    "patterns" => [
      "/raw\.githubusercontent\.com\/xkaze-jpg\/Manjaku\/Manjaku\/tes\.txt/i",
      "/sys_get_temp_dir\s*\(/i",
      "/uniqid\s*\(/i",
      "/include\s*\(/i",
      "/unlink\s*\(/i"
    ],
    "risk" => "high",
    "label" => "Backdoor #3: GitHub temp file loader"
  ],

  // === BACKDOOR 4: gx-d3f.pages.dev/autoload2.php
  [
    "patterns" => [
      "/https:\/\/gx-d3f\.pages\.dev\/autoload2\.php/i",
      "/file_get_contents\s*\(/i",
      "/eval\s*\(\s*['\"]\?\>\s*\.\s*\$api\s*\)/i"
    ],
    "risk" => "high",
    "label" => "Backdoor #4: gx-d3f autoload2.php loader"
  ]
];