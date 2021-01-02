package session

// ReasonPhrase .
var ReasonPhrase = map[uint16]string{
	100: "Trying",
	180: "Ringing",
	181: "Call Is Being Forwarded",
	182: "Queued",
	183: "Session Progress",
	199: "Early Dialog Terminated", // draft-ietf-sipcore-199
	200: "OK",
	202: "Accepted",        // RFC 3265
	204: "No Notification", // RFC 5839
	300: "Multiple Choices",
	301: "Moved Permanently",
	302: "Moved Temporarily",
	305: "Use Proxy",
	380: "Alternative Service",
	400: "Bad Request",
	401: "Unauthorized",
	402: "Payment Required",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	406: "Not Acceptable",
	407: "Proxy Authentication Required",
	408: "Request Timeout",
	410: "Gone",
	412: "Conditional Request Failed", // RFC 3903
	413: "Request Entity Too Large",
	414: "Request-URI Too Long",
	415: "Unsupported Media Type",
	416: "Unsupported URI Scheme",
	417: "Unknown Resource-Priority", // RFC 4412
	420: "Bad Extension",
	421: "Extension Required",
	422: "Session Interval Too Small", // RFC 4028
	423: "Interval Too Brief",
	424: "Bad Location Information",         // RFC 6442
	428: "Use Identity Header",              // RFC 4474
	429: "Provide Referrer Identity",        // RFC 3892
	430: "Flow Failed",                      // RFC 5626
	433: "Anonymity Disallowed",             // RFC 5079
	436: "Bad Identity-Info",                // RFC 4474
	437: "Unsupported Certificate",          // RFC 4744
	438: "Invalid Identity Header",          // RFC 4744
	439: "First Hop Lacks Outbound Support", // RFC 5626
	440: "Max-Breadth Exceeded",             // RFC 5393
	469: "Bad Info Package",                 // draft-ietf-sipcore-info-events
	470: "Consent Needed",                   // RFC 5360
	478: "Unresolvable Destination",         // Custom code copied from Kamailio.
	480: "Temporarily Unavailable",
	481: "Call/Transaction Does Not Exist",
	482: "Loop Detected",
	483: "Too Many Hops",
	484: "Address Incomplete",
	485: "Ambiguous",
	486: "Busy Here",
	487: "Request Terminated",
	488: "Not Acceptable Here",
	489: "Bad Event", // RFC 3265
	491: "Request Pending",
	493: "Undecipherable",
	494: "Security Agreement Required", // RFC 3329
	500: "DartSIP Internal Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Server Time-out",
	505: "Version Not Supported",
	513: "Message Too Large",
	580: "Precondition Failure", // RFC 3312
	600: "Busy Everywhere",
	603: "Decline",
	604: "Does Not Exist Anywhere",
	606: "Not Acceptable",
}

const (
	AllowedMethods    = "INVITE,ACK,CANCEL,BYE,UPDATE,MESSAGE,OPTIONS,REFER,INFO"
	AcceptedBody      = "application/sdp, application/dtmf-relay"
	MaxForwards       = 69
	SessionExpires    = 90
	MinSessionExpires = 60
)

type Status string

const (
	InviteSent       Status = "InviteSent"       /**< After INVITE s sent */
	InviteReceived   Status = "InviteReceived"   /**< After INVITE s received. */
	ReInviteReceived Status = "ReInviteReceived" /**< After re-INVITE/UPDATE s received */
	//Answer         Status = "Answer"           /**< After response for re-INVITE/UPDATE. */
	Provisional      Status = "Provisional" /**< After response for 1XX. */
	EarlyMedia       Status = "EarlyMedia"  /**< After response 1XX with sdp. */
	WaitingForAnswer Status = "WaitingForAnswer"
	WaitingForACK    Status = "WaitingForACK" /**< After 2xx s sent/received. */
	Answered         Status = "Answered"
	Canceled         Status = "Canceled"
	Confirmed        Status = "Confirmed"  /**< After ACK s sent/received. */
	Failure          Status = "Failure"    /**< Session s rejected or canceled. */
	Terminated       Status = "Terminated" /**< Session s terminated. */
)

type Direction string

const (
	Outgoing Direction = "Outgoing"
	Incoming Direction = "Incoming"
)
