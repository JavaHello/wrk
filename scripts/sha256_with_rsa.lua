-- example HTTP POST script which demonstrates setting the
-- HTTP method, body, and adding a header
--
function init()
	wrk.add_private_key(0, "./private-key.pem")
end

wrk.method = "POST"
wrk.body = "hello world"
wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"

request = function()
  local sign = wrk.sha256_with_rsa(0, wrk.body)
	wrk.headers["X-Signtrue"] = sign;
	wrk.headers["X-Signtrue2"] = wrk.sha256(wrk.body);
	return wrk.format()
end
