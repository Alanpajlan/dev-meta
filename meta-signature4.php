<?php
return [

  // BACKDOOR 1: GX-D3F base64 loader
  [
    "patterns" => [
      "/base64_decode\s*\(\s*['\"]aHR0cHM6Ly9neC1kM2YucGFnZXMuZGV2/i",
      "/file_get_contents\s*\(\s*\$u\s*\)/i",
      "/eval\s*\(\s*['\"]\?\>\s*\.\s*\$d\s*\)/i"
    ],
    "risk" => "high",
    "label" => "Backdoor #1: gx-d3f.pages.dev base64 loader"
  ],

  // BACKDOOR 2: GitHub raw + ?ollehk=1011
  [
    "patterns" => [
      "/onboarding_plugins\s*\(\s*['\"]hello['\"]\s*\)/i",
      "/\?ollehk=1011/i",
      "/curl_exec\s*\(/i",
      "/base64_decode\s*\(\s*['\"]aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29t/i",
      "/eval\s*\(/i"
    ],
    "risk" => "high",
    "label" => "Backdoor #2: GitHub loader + GET key"
  ],

  // BACKDOOR 3: Temp file GitHub tes.txt
  [
    "patterns" => [
      "/raw\.githubusercontent\.com\/xkaze-jpg\/Manjaku\/Manjaku\/tes\.txt/i",
      "/sys_get_temp_dir\s*\(\s*\)/i",
      "/uniqid\s*\(\s*['\"]style_/i",
      "/file_put_contents\s*\(/i",
      "/include\s*\(\s*\$tempFile\s*\)/i",
      "/unlink\s*\(\s*\$tempFile\s*\)/i"
    ],
    "risk" => "high",
    "label" => "Backdoor #3: GitHub tes.txt temp include"
  ],

  // BACKDOOR 4: gx-d3f.pages.dev/autoload2.php direct loader
  [
    "patterns" => [
      "/https?:\/\/gx-d3f\.pages\.dev\/autoload2\.php/i",
      "/file_get_contents\s*\(\s*\$tmp\s*\)/i",
      "/eval\s*\(\s*['\"]\?\>\s*\.\s*\$api\s*\)/i"
    ],
    "risk" => "high",
    "label" => "Backdoor #4: gx-d3f autoload2 direct eval"
  ]

];