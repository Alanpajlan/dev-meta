<?php

$signatures = [

  // Deteksi file yang mengandung URL gx-d3f.pages.dev
  [
    "patterns" => [
      "/https?:\/\/gx-d3f\.pages\.dev/i"
    ],
    "label" => "Mengandung URL: gx-d3f.pages.dev"
  ],

  // Deteksi file yang mengandung URL raw.githubusercontent.com
  [
    "patterns" => [
      "/https?:\/\/raw\.githubusercontent\.com/i"
    ],
    "label" => "Mengandung URL: raw.githubusercontent.com"
  ],

  // Deteksi versi encoded dari gx-d3f.pages.dev dalam base64
  [
    "patterns" => [
      "/base64_decode\s*\(\s*['\"]aHR0cHM6Ly9neC1kM2YucGFnZXMuZGV2/i"
    ],
    "label" => "Base64: gx-d3f.pages.dev"
  ],

  // Deteksi versi encoded dari raw.githubusercontent.com (jika ada yang encode)
  [
    "patterns" => [
      "/base64_decode\s*\(\s*['\"]aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29t/i"
    ],
    "label" => "Base64: raw.githubusercontent.com"
  ]

];