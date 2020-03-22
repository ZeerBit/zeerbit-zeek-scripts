##! Enriched known_hosts logging in an extended format with DNS PTR results added

@load base/frameworks/cluster

module Known;

export {
	## You can adjust known_hosts record expiration here, ZeerHosts expiration will be (and has to be) derived from this value
	#redef host_store_expiry = 15min;
  
  # Making KnownHosts store persistent. This will make sure ZeerHosts and KnownHosts 
  # record expiration times are the same between Zeek restarts.
  redef Cluster::stores += {
    [Known::host_store_name] = Cluster::StoreInfo($backend = Broker::SQLITE)
  };
}

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

	## Holds the set of hosts. Keys in the store are addresses
	## and their associated value will always be the "true" boolean.
	global host_store: Cluster::StoreInfo;

	## The Broker topic name to use for :zeek:see:`ZeerHosts::host_store`.
	const host_store_name = "zeek/zeer/hosts" &redef;

  ## The expiry interval of new entries in :zeek:see:`ZeerHosts::host_store`.
	## This also changes the interval at which hosts get logged.
	const host_store_expiry = Known::host_store_expiry &redef;
  
  # Expiration date for ZeerHosts should be close but shorter then the one for KnownHosts,
  ## otherwise if it happens later, add_host will fail due to uniqueness check
  const host_store_expiry_shift = 2sec &redef;
    
	## The timeout interval to use for operations against
	## :zeek:see:`ZeerHosts::host_store`.
	option host_store_timeout = 15sec;

	## The timeout interval to use for DNS lookup operations
	option dns_lookup_timeout = 5sec;
  
  global ZeerHosts::add_host: event(rec: Info);
}

event zeek_init() {
  # Initialize the persistent store
	ZeerHosts::host_store = Cluster::create_store(ZeerHosts::host_store_name, T);
}

event zeek_init() &priority=5 {
  # Create the logging stream.
  Log::create_stream(LOG, [$columns=Info, $path="zeer_hosts"]);
}

event ZeerHosts::add_host(rec: ZeerHosts::Info) {
  # Consider using event handlers instead of 'when' for performance reasons
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
