##! Add GEO data for the originator and responder of a connection
##! to the connection logs.

# Based on https://github.com/zeek/bro-scripts/blob/master/conn-add-geodata.bro by Seth Hall

module Conn;

export {
	redef record Conn::Info += {
		## Longitude and latitude for the originator of the connection based on a GeoIP lookup.
		orig_geo_lon: double &optional &log;
		orig_geo_lat: double &optional &log;
		## Longitude and latitude for the responder of the connection based on a GeoIP lookup.
		resp_geo_lon: double &optional &log;
		resp_geo_lat: double &optional &log;
	};
}

event connection_state_remove(c: connection) 
	{
	local orig_loc = lookup_location(c$id$orig_h);
	if ( orig_loc?$longitude )
		c$conn$orig_geo_lon = orig_loc$longitude;
	if ( orig_loc?$latitude )
		c$conn$orig_geo_lat = orig_loc$latitude;

	local resp_loc = lookup_location(c$id$resp_h);
	if ( resp_loc?$longitude )
		c$conn$resp_geo_lon = resp_loc$longitude;
	if ( resp_loc?$latitude )
		c$conn$resp_geo_lat = resp_loc$latitude;
	}
