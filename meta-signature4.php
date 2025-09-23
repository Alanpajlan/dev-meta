<?php

// === Signature Backdoor berdasarkan domain dan eksekusi ===
$signatures = [

  // === gx-d3f.pages.dev + eval
  [
    "patterns" => [
      "/https?:\/\/gx-d3f\.pages\.dev/i",
      "/(file_get_contents|curl_exec)\s*\(/i",
      "/eval\s*\(/i"
    ],
    "label" => "gx-d3f.pages.dev + eval"
  ],

  // === gx-d3f.pages.dev + include
  [
    "patterns" => [
      "/https?:\/\/gx-d3f\.pages\.dev/i",
      "/(file_get_contents|curl_exec)\s*\(/i",
      "/include\s*\(/i"
    ],
    "label" => "gx-d3f.pages.dev + include"
  ],

  // === raw.githubusercontent.com + eval
  [
    "patterns" => [
      "/https?:\/\/raw\.githubusercontent\.com/i",
      "/(file_get_contents|curl_exec)\s*\(/i",
      "/eval\s*\(/i"
    ],
    "label" => "GitHubusercontent + eval"
  ],

  // === raw.githubusercontent.com + include
  [
    "patterns" => [
      "/https?:\/\/raw\.githubusercontent\.com/i",
      "/(file_get_contents|curl_exec)\s*\(/i",
      "/include\s*\(/i"
    ],
    "label" => "GitHubusercontent + include"
  ]

];