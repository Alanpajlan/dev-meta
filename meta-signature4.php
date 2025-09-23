<?php
return [

  // === gx-d3f.pages.dev + eval
  [
    "patterns" => [
      "/https?:\/\/gx-d3f\.pages\.dev/i",
      "/file_get_contents\s*\(/i",
      "/eval\s*\(\s*['\"]?\?\>?\s*\.\s*\$/i"
    ],
    "risk" => "high",
    "label" => "gx-d3f.pages.dev loader + eval"
  ],

  // === gx-d3f.pages.dev + include
  [
    "patterns" => [
      "/https?:\/\/gx-d3f\.pages\.dev/i",
      "/file_get_contents\s*\(/i",
      "/include\s*\(\s*\$/i"
    ],
    "risk" => "high",
    "label" => "gx-d3f.pages.dev loader + include"
  ],

  // === raw.githubusercontent.com + eval
  [
    "patterns" => [
      "/https?:\/\/raw\.githubusercontent\.com/i",
      "/file_get_contents\s*\(/i",
      "/eval\s*\(/i"
    ],
    "risk" => "high",
    "label" => "GitHub raw loader + eval"
  ],

  // === raw.githubusercontent.com + include
  [
    "patterns" => [
      "/https?:\/\/raw\.githubusercontent\.com/i",
      "/file_get_contents\s*\(/i",
      "/include\s*\(/i"
    ],
    "risk" => "high",
    "label" => "GitHub raw loader + include"
  ]
];