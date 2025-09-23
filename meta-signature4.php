<?php
return [
  // === BACKDOOR 1: GX-D3F loader via base64_decode + file_get_contents + eval
  [
    "patterns" => [
      "/base64_decode\s*\(\s*['\"]aHR0cHM6Ly9neC1kM2YucGFnZXMuZGV2/i",
      "/file_get_contents\s*\(/i",
      "/eval\s*\(\s*['\"]\?\>.*?\)/is"
    ],
    "risk" => "high",
    "label" => "GX-D3F loader (encoded URL + eval)"
  ],

  // === BACKDOOR 2: GitHub raw loader with GET-auth (?ollehk=1011)
  [
    "patterns" => [
      "/onboarding_plugins\s*\(/i",
      "/\?ollehk=1011/i",
      "/curl_exec\s*\(/i",
      "/eval\s*\(/i",
      "/base64_decode\s*\(\s*['\"]aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29t/i"
    ],
    "risk" => "high",
    "label" => "GitHub raw + GET key backdoor (ollehk=1011)"
  ],

  // === BACKDOOR 3: Temp file loader from GitHub raw (tes.txt)
  [
    "patterns" => [
      "/raw\.githubusercontent\.com\/xkaze-jpg\/Manjaku/i",
      "/sys_get_temp_dir\s*\(/i",
      "/uniqid\s*\(/i",
      "/file_put_contents\s*\(/i",
      "/include\s*\(/i",
      "/unlink\s*\(/i"
    ],
    "risk" => "high",
    "label" => "Temp file loader (GitHub Manjaku/tes.txt)"
  ],

  // === BACKDOOR 4: GX-D3F autoload2.php (no encoding, direct eval)
  [
    "patterns" => [
      "/https?:\/\/gx-d3f\.pages\.dev\/autoload2\.php/i",
      "/file_get_contents\s*\(\s*\$?(tmp|url)?\s*\)?\s*;/i",
      "/eval\s*\(\s*['\"]\?\>.*?\)/is"
    ],
    "risk" => "high",
    "label" => "GX-D3F autoload2 loader (direct file_get_contents + eval)"
  ]
];