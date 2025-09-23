<?php
return [

  // === BACKDOOR 1: GX-D3F loader via base64_decode + file_get_contents + eval
  [
    "patterns" => [
      "/file_get_contents\s*\(\s*base64_decode\s*\(\s*['\"]aHR0cHM6Ly9neC1kM2YucGFnZXMuZGV2/i",
      "/eval\s*\(\s*['\"]\?\>\s*\.\s*\$d\s*\)/i"
    ],
    "risk" => "high",
    "label" => "Backdoor #1: gx-d3f.pages.dev base64 remote eval"
  ],

  // === BACKDOOR 2: GitHub raw loader with GET-auth (?ollehk=1011)
  [
    "patterns" => [
      "/onboarding_plugins\s*\(\s*['\"]hello['\"]\s*\)/i",
      "/\$_GET\s*\[\s*\$Installer\s*\]/i",
      "/base64_decode\s*\(\s*['\"]aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29t/i",
      "/eval\s*\(\s*\$htmlChars\s*\)/i"
    ],
    "risk" => "high",
    "label" => "Backdoor #2: GitHub raw + GET auth + eval"
  ],

  // === BACKDOOR 3: Temp file loader from GitHub raw (tes.txt)
  [
    "patterns" => [
      "/raw\.githubusercontent\.com\/xkaze-jpg\/Manjaku\/Manjaku\/tes\.txt/i",
      "/sys_get_temp_dir\s*\(\s*\)/i",
      "/include\s*\(\s*\$tempFile\s*\)/i",
      "/unlink\s*\(\s*\$tempFile\s*\)/i"
    ],
    "risk" => "high",
    "label" => "Backdoor #3: GitHub tes.txt loader with temp file include"
  ],

  // === BACKDOOR 4: gx-d3f.pages.dev/autoload2.php
  [
    "patterns" => [
      "/file_get_contents\s*\(\s*['\"]https:\/\/gx-d3f\.pages\.dev\/autoload2\.php['\"]\s*\)/i",
      "/eval\s*\(\s*['\"]\?\>\s*\.\s*\$api\s*\)/i"
    ],
    "risk" => "high",
    "label" => "Backdoor #4: gx-d3f autoload2 direct eval"
  ]

];