##! Add GEO data for the originator and responder of a connection
##! to the connection logs.

# Based on https://github.com/zeek/bro-scripts/blob/master/conn-add-geodata.bro by Seth Hall

module Conn;

export {
	redef record Conn::Info += {
		## Geodata for the originator of the connection based on a GeoIP lookup.
		orig_geo_lon: double &optional &log;
		orig_geo_lat: double &optional &log;
		orig_geo_cc: string &optional &log;
    
		## Geodata for the responder of the connection based on a GeoIP lookup.
		resp_geo_lon: double &optional &log;
		resp_geo_lat: double &optional &log;
		resp_geo_cc: string &optional &log;
    
	};
}

# For geodata to work, local_nets have to be defined for the site.
# Only non-local IPs are enriched with geodata

event connection_state_remove(c: connection) {
  if (|Site::local_nets| > 0) {
    if (c$id?$orig_h && ! Site::is_local_addr(c$id$orig_h)) {
    	local orig_loc = lookup_location(c$id$orig_h);
    	if ( orig_loc?$longitude )
    		c$conn$orig_geo_lon = orig_loc$longitude;
    	if ( orig_loc?$latitude )
    		c$conn$orig_geo_lat = orig_loc$latitude;
    	if ( orig_loc?$country_code )
    		c$conn$orig_geo_cc = orig_loc$country_code;
    }
    if (c$id?$resp_h && ! Site::is_local_addr(c$id$resp_h)) {
    	local resp_loc = lookup_location(c$id$resp_h);
    	if ( resp_loc?$longitude )
    		c$conn$resp_geo_lon = resp_loc$longitude;
    	if ( resp_loc?$latitude )
    		c$conn$resp_geo_lat = resp_loc$latitude;
    	if ( resp_loc?$country_code )
    		c$conn$resp_geo_cc = resp_loc$country_code;
    }
  }
}
