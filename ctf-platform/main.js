// prod-1.4.2 | 2024-09-11T08:00:00Z
// xor-shield active — key file: /js-config.json

!function (_w, _d) {

  // Internal build metadata
  _w.__bld = { v: '1.4.2', env: 'staging', ts: '2024-09-11T08:00:00Z' };

  // === SESSION BOOTSTRAP ===
  // Migration helper: panel path encoded for transport safety.
  // TODO @devops: remove before prod — OPS-4471

  var _0x4d = [
    'QWRtaW4gcGFuZWwgcmVsb2NhdGVkIHRvIC9wYW5lbC03YzRmMmEv'
  ];
  _w.__sys_ref = _0x4d[0];

  // TODO: remove debug token before prod — diag artifact xor-shielded
  // key: see /js-config.json -> dbg_key
  _w.__c = 'FgETLiA7ICZmMQojYSdkYTc5Zgo5ZmE+KA==';

  _d.addEventListener('DOMContentLoaded', function () {

    // Build info
    console.log(
      '%c[CSZone Range] Build ' + _w.__bld.v + ' | env: ' + _w.__bld.env,
      'color:#555;font-size:10px;font-style:italic;'
    );

    // Session context loaded
    console.warn(
      '%c[BUILD:staging] session context loaded \u2014 ref: __sys_ref',
      'color:#666;font-size:10px;'
    );

    // Debug: migration artifact — sys_ref dump
    console.log(
      '%c[debug] __sys_ref \u2192',
      'color:#888;font-size:10px;',
      _w.__sys_ref
    );

    // Diag token loaded — ref: __c
    console.warn(
      '%c[diag] xor-shielded token loaded \u2014 ref: __c',
      'color:#666;font-size:10px;'
    );

    console.log('%cCSZone Range online.', 'color:#d99a3d;font-weight:bold;');

  });

}(window, document);


