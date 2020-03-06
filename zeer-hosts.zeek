##! Enriched known_hosts logging in an extended format with DNS PTR results added

module ZeerHosts;

export {
  # Append the value LOG to the Log::ID enumerable.
  redef enum Log::ID += { LOG };

  # Define a new type called ZeerHosts::Info.
  type Info: record {
      ts: time &log;
      host_ip: addr &log;
  		host_fqdn: string &optional &log;
    };
}

event zeek_init() {
  # Create the logging stream.
  Log::create_stream(LOG, [$columns=Info, $path="zeer_hosts"]);
}

module Known;

event log_known_hosts(rec: Known::HostsInfo) {
  if (|Site::local_nets| > 0) {
    if (rec?$host && Site::is_local_addr(rec$host)) {
      when (local resolved_name = lookup_addr(rec$host)) { 
        if (resolved_name != "<???>") {
          Log::write(ZeerHosts::LOG, [$ts = rec$ts, $host_ip = rec$host, $host_fqdn = resolved_name]);
        } else {
          Log::write(ZeerHosts::LOG, [$ts = rec$ts, $host_ip = rec$host]);
        }
      }
    }
  }
}
