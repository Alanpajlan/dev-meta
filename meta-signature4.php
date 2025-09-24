<?php
return [

  // gx-d3f.pages.dev (langsung)
  [
    'pattern' => '/https?:\/\/gx-d3f\.pages\.dev/i',
    'risk'    => 'high',
    'label'   => 'URL: gx-d3f.pages.dev'
  ],

  // raw.githubusercontent.com (langsung)
  [
    'pattern' => '/https?:\/\/raw\.githubusercontent\.com/i',
    'risk'    => 'high',
    'label'   => 'URL: raw.githubusercontent.com'
  ],

  // base64 gx-d3f.pages.dev
  [
    'pattern' => '/base64_decode\s*\(\s*["\']aHR0cHM6Ly9neC1kM2YucGFnZXMuZGV2/i',
    'risk'    => 'high',
    'label'   => 'Base64: gx-d3f.pages.dev'
  ],

  // base64 raw.githubusercontent.com
  [
    'pattern' => '/base64_decode\s*\(\s*["\']aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29t/i',
    'risk'    => 'high',
    'label'   => 'Base64: raw.githubusercontent.com'
  ],

];