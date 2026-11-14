package upstream

// JavaScriptTransportForTest lets external integration tests route the broker to
// an in-process fake provider without allowing private origins in production.
var JavaScriptTransportForTest = &javascriptTransport
