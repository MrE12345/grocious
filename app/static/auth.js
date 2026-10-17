/* Attach the session CSRF token to same-origin changes and regular HTML forms. */
(function () {
  var node = document.querySelector('meta[name="csrf-token"]');
  if (!node || !node.content) return;
  var token = node.content;
  var original = window.fetch;
  window.fetch = function (input, options) {
    var req = new Request(input, options);
    if (new URL(req.url).origin === location.origin && !/^(GET|HEAD|OPTIONS)$/i.test(req.method)) {
      var headers = new Headers(req.headers);
      headers.set("X-CSRF-Token", token);
      req = new Request(req, {headers: headers});
    }
    return original.call(window, req);
  };
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement) || form.method.toLowerCase() === "get" ||
        new URL(form.action, location.href).origin !== location.origin) return;
    var field = form.querySelector('input[name="csrf_token"]');
    if (!field) {
      field = document.createElement("input"); field.type = "hidden"; field.name = "csrf_token";
      form.appendChild(field);
    }
    field.value = token;
  }, true);
})();
