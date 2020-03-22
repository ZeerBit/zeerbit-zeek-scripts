##! Add FQDN data for the originator and/or responder of a connection
##! to the connection logs - for local addr only. Based on zeer-hosts FQDN cache

@load base/init-bare
@load base/protocols/conn
@load zeerbit-zeek-scripts/zeer-hosts

export {
  type host_info: record {
  	host_fqdn: string &optional;
  };
    
	redef record connection += {
    orig_info: host_info &optional;
    resp_info: host_info &optional;
  };
}

module Conn;

export {
	redef record Conn::Info += {
		## FQDN for the originator of the connection
		orig_fqdn: string &optional &log;
    
		## FQDN for the responder of the connection
		resp_fqdn: string &optional &log;
    
	};
}

# For zeer-hosts to work, local_nets have to be defined for the site.
# Only local IPs are enriched with FQDN at this point
# Starting with 3.1 connection_successful would be the best event to catch

event connection_established(c: connection) {
  if (|Site::local_nets| > 0) {
    if (c$id?$orig_h && Site::is_local_addr(c$id$orig_h)) {
    	when (local zeer_hosts_orig = Broker::get(ZeerHosts::host_store$store, c$id$orig_h)) {
        local conn_orig = lookup_connection(c$id);
        if (zeer_hosts_orig$status == Broker::SUCCESS && zeer_hosts_orig?$result && zeer_hosts_orig$result?$data) {
          conn_orig$orig_info = [$host_fqdn = zeer_hosts_orig$result as string];
        }
      } timeout ZeerHosts::host_store_timeout {
    		Reporter::error(fmt("ZeerHosts data store lookup timeout for %s", c$id$orig_h));
      }
    }
    if (c$id?$resp_h && Site::is_local_addr(c$id$resp_h)) {
    	when (local zeer_hosts_resp = Broker::get(ZeerHosts::host_store$store, c$id$resp_h)) {
        local conn_resp = lookup_connection(c$id);
        if (zeer_hosts_resp$status == Broker::SUCCESS && zeer_hosts_resp?$result && zeer_hosts_resp$result?$data) {
          conn_resp$resp_info = [$host_fqdn = zeer_hosts_resp$result as string];
        }
      } timeout ZeerHosts::host_store_timeout {
    		Reporter::error(fmt("ZeerHosts data store lookup timeout for %s", c$id$resp_h));
      }
    }
  }
}

event connection_state_remove(c: connection) {
  if (c?$orig_info && c$orig_info?$host_fqdn && c?$conn) {
    c$conn$orig_fqdn = c$orig_info$host_fqdn;
  }
  if (c?$resp_info && c$resp_info?$host_fqdn && c?$conn) {
    c$conn$resp_fqdn = c$resp_info$host_fqdn;
  }
}