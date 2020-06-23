##! Add FQDN data for the originator and/or responder of a connection
##! to the connection logs - for local addr only. Based on zeer-hosts FQDN cache

@load base/init-bare
@load base/protocols/conn
@load zeerbit-zeek-scripts/zeer-hosts

export {
  type host_info: record {
    host_fqdn: string &optional;
    was_attempted: bool &optional &default=F;
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

function add_host_info(c: connection, host_role: string) {
  if (|Site::local_nets| > 0) {
    local host_ip: addr;
    local try_lookup: bool; # Workaround to see if host_ip was initialiazed and we should try looking up an fqdn for it
    try_lookup = F;
    if (host_role == "orig" && c$id?$orig_h && Site::is_local_addr(c$id$orig_h)) {
      host_ip = c$id$orig_h;
      try_lookup = T;
    } else if (host_role == "resp" && c$id?$resp_h && Site::is_local_addr(c$id$resp_h)) {
      host_ip = c$id$resp_h;    
      try_lookup = T;
    }
    # WARNING: calling is_v4_addr or is_v6_addr over uninitialized addr will cause memory leak
    if (try_lookup && (is_v4_addr(host_ip) || is_v6_addr(host_ip))) { 
      when (local r = Broker::get(ZeerHosts::host_store$store, host_ip)) {
        local conn = lookup_connection(c$id);
        local h: host_info;
        if (r$status == Broker::SUCCESS && r?$result && r$result?$data) {
          h = [$host_fqdn = r$result as string, $was_attempted = T];
        } else {
          h = [$was_attempted = T];
        }
        if (host_role == "orig") {
          conn$orig_info = h;
        } else if (host_role == "resp") {
          conn$resp_info = h;
        }
      } timeout ZeerHosts::host_store_timeout {
        Reporter::error(fmt("ZeerHosts data store lookup timeout for %s", host_ip));
        local conn_t = lookup_connection(c$id);
        if (host_role == "orig") {
          conn_t$orig_info = [$was_attempted = T];
        } else if (host_role == "resp") {
          conn_t$resp_info = [$was_attempted = T];
        }
      }
    }
  }
}

# Starting with 3.1 connection_successful would be the best event to catch
event connection_successful(c: connection) {
  if (!c?$orig_info || !c$orig_info?$was_attempted || !c$orig_info$was_attempted) {
    add_host_info(c, "orig");
  }
  if (!c?$resp_info || !c$resp_info?$was_attempted || !c$resp_info$was_attempted) {
    add_host_info(c, "resp");
  }
}

# Pririo to 3.1 connection_established would work, but only for TCP connections
event connection_established(c: connection) {
  if (!c?$orig_info || !c$orig_info?$was_attempted || !c$orig_info$was_attempted) {
    add_host_info(c, "orig");
  }
  if (!c?$resp_info || !c$resp_info?$was_attempted || !c$resp_info$was_attempted) {
    add_host_info(c, "resp");
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