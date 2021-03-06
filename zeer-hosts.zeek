##! Enriched known_hosts logging in an extended format with DNS PTR results added

@load base/frameworks/cluster

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

  ## Holds mappings between host IP addresses and their hostnames. 
  ## Keys in the store are addresses and their associated value are hostnames.
  global host_store: Cluster::StoreInfo;

  ## The Broker topic name to use for ZeerHosts::host_store.
  const host_store_name = "zeek/zeer/hosts" &redef;

  ## The expiry interval of new entries in ZeerHosts::host_store.
  ## This also changes the interval at which hosts get logged.
  const host_store_expiry = Known::host_store_expiry &redef;
  
  ## Expiration date for records in ZeerHosts::host_store should be close but shorter 
  ## than the one for KnownHosts::host_store, otherwise if it expires later, 
  ## adding the same host again will fail due to uniqueness check.
  const host_store_expiry_shift = 2sec &redef;
    
  ## The timeout interval to use for operations against ZeerHosts::host_store.
  option host_store_timeout = 15sec;

  ## The timeout interval to use for DNS lookup operations
  option dns_lookup_timeout = 5sec;
  
  global ZeerHosts::add_host: event(rec: Info);
}

event zeek_init() {
  # Initialize the ZeekHosts store (see documentation on how to make it persistent)
  ZeerHosts::host_store = Cluster::create_store(ZeerHosts::host_store_name);
}

event zeek_init() &priority=5 {
  # Create the logging stream.
  Log::create_stream(LOG, [$columns=Info, $path="zeer_hosts"]);
}

event ZeerHosts::add_host(rec: ZeerHosts::Info) {
  when (local r = Broker::put_unique(ZeerHosts::host_store$store, 
                                     rec$host_ip, 
                                     rec$host_fqdn, 
                                     ZeerHosts::host_store_expiry - (current_time() - rec$ts) - host_store_expiry_shift)) {
    if (r$status == Broker::SUCCESS && r$result as bool) {
      Log::write(ZeerHosts::LOG, rec);
    }
    else {
      Reporter::error(fmt("%s: data store put_unique failure", ZeerHosts::host_store_name));
    }
  } timeout ZeerHosts::host_store_timeout {
    # Can't really tell if master store ended up inserting a key.
    Log::write(ZeerHosts::LOG, rec);
  }
}

module Known;

event log_known_hosts(rec: Known::HostsInfo) {
  if (|Site::local_nets| > 0) {
    if (rec?$host && Site::is_local_addr(rec$host)) {
      when (local resolved_name = lookup_addr(rec$host)) {
      
        if (resolved_name != "" && resolved_name != "<???>") {
        
          event ZeerHosts::add_host([$ts = rec$ts, $host_ip = rec$host, $host_fqdn = resolved_name]);
          
        } else {
          # If not resolved, log but don't store:
          # Store is a cache used to enrich conn.log with FQDN by Zeek, so we don't need unresolved entries there;
          # zeer_hosts.log, on the other hand, is an enriched replacement for known_hosts.log, ingressed into SIEM
          # to create an inventory of observed hosts, no matter with or without FQDN. It is up to log ingest pipeline
          # to decide how to heandle missing FDQN in zeer_hosts.log
          
          Log::write(ZeerHosts::LOG, [$ts = rec$ts, $host_ip = rec$host]);

        }
        
      } timeout ZeerHosts::dns_lookup_timeout {
      
          Log::write(ZeerHosts::LOG, [$ts = rec$ts, $host_ip = rec$host]);

      }
    }
  }
}
