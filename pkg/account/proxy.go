package account

import "github.com/ghettovoice/gosip/sip"

type ProxiesConfig struct {
	/*
	* Specify the URL of outbound proxies to visit for all outgoing requests.
	* The outbound proxies will be used for a account.Profile.
	 */
	OutboundProxes []sip.Uri
	/* Force loose-route to be used in all route/proxy URIs (outbound_proxy
	 * and account's proxy settings). Append ";lr" parameter to the URI.
	 */
	ForceLooseRoute bool
}
