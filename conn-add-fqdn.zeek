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
	#Reporter::info(fmt("Connection established: from %s to %s", c$id$orig_h, c$id$resp_h));
  if (|Site::local_nets| > 0) {
    if (c$id?$orig_h && Site::is_local_addr(c$id$orig_h)) {
    	when (local r = Broker::get(ZeerHosts::host_store$store, c$id$orig_h)) {
        local conn = lookup_connection(c$id);
        if (r$status == Broker::SUCCESS && r?$result && r$result?$data) {
          conn$orig_info = [$host_fqdn = r$result as string];
      		#Reporter::info(fmt("ZeerHosts data store successful hit for %s: %s", conn$id$orig_h, conn$orig_info$host_fqdn));
        } else {
      		#Reporter::info(fmt("ZeerHosts data store no hits for %s", conn$id$orig_h));
        }
      } timeout ZeerHosts::host_store_timeout {
    		Reporter::error(fmt("ZeerHosts data store lookup timeout for %s", c$id$orig_h));
      }
    }
  }
}

event connection_state_remove(c: connection) {
  #if (!c?$orig_info && c?$conn) {
	#	Reporter::info(fmt("On connection remove, c$orig_info does not exists for connection: from %s to %s", c$id$orig_h, c$id$resp_h));
  #}
  if (c?$orig_info && c$orig_info?$host_fqdn && c?$conn) {
		#Reporter::info(fmt("On connection remove, c$orig_info$host_fqdn: %s", c$orig_info$host_fqdn));
    c$conn$orig_fqdn = c$orig_info$host_fqdn;
  }
}