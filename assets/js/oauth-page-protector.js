(function ($) {
  "use strict";

  $(document).ready(function () {
    if (typeof oppData !== "undefined" && oppData.authToken) {
      // Send the auth token to the Chrome extension
      window.postMessage(
        {
          type: "OPP_AUTH_TOKEN",
          token: oppData.authToken,
        },
        "*"
      );
    }
  });
})(jQuery);
