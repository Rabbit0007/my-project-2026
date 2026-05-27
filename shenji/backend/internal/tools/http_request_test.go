package tools

import (
	"strings"
	"testing"
)

func TestParseHTTPResponseKeepsHTMLBodyWithBlankLines(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/html\r\n\r\n" +
		"<html>\r\n<body>\r\n\r\n\r\n<font>You have an error in your SQL syntax</font>\r\n\r\n</body>\r\n</html>\r\n" +
		"\n__RABBIT_STATUS__:200"

	status, headers, body := parseHTTPResponse(raw)
	if status != 200 {
		t.Fatalf("expected status 200, got %d", status)
	}
	if headers["Server"][0] != "Apache" {
		t.Fatalf("expected Server header, got %+v", headers)
	}
	if !strings.Contains(body, "You have an error in your SQL syntax") {
		t.Fatalf("expected full HTML body with SQL error, got %q", body)
	}
}
