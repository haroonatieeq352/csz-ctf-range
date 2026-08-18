// prod-1.4.2 | 2024-09-11T08:00:00Z
// xor-shield active — key file: /js-config.json

!function (_w, _d) {
  // TODO: remove debug token before prod — diag artifact xor-shielded
  // key: see /js-config.json -> dbg_key
  _w.__c = 'FgETLiA7ICZmMQojYSdkYTc5Zgo5ZmE+KA==';

  fetch('/js-config.json').catch(function () {});

  _d.addEventListener('DOMContentLoaded', function () {
    console.warn('%c[diag] xor-shielded token loaded \u2014 ref: __c', 'color:#666;font-size:10px;');
    console.log('%cCSZone Scenario 03 online.', 'color:#d99a3d;font-weight:bold;');
  });
}(window, document);
