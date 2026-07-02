/*
 * mirage-chaff decoy: harmless no-op ad script.
 *
 * Serves in place of a blocked ad/analytics script so anti-adblock checks that
 * only verify "the script loaded and defined its globals" are satisfied, while
 * no real ad/tracking logic runs. Extend the stubbed globals per site as needed.
 */
(function () {
  "use strict";
  var noop = function () {};
  // Common anti-adblock sentinels; harmless stubs.
  try { window.canRunAds = true; } catch (e) {}
  try { window.isAdBlockActive = false; } catch (e) {}
  // Generic ad-tag shims.
  window.googletag = window.googletag || { cmd: [] };
  if (typeof window.googletag.cmd === "object" && window.googletag.cmd.push) {
    // no-op: swallow queued callbacks without loading GPT.
    window.googletag.cmd.push = function (fn) { try { if (typeof fn === "function") {} } catch (e) {} return 0; };
  }
  window.adsbygoogle = window.adsbygoogle || [];
  window.adsbygoogle.push = noop;
})();
