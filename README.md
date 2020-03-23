# zeerbit-zeek-scripts
A collection of Zeek customization scripts

## ZeerHosts
ZeerHosts (`zeer_hosts.log`) is an enriched version of KnownHosts (`known_hosts.log`), with FQDN information collected via DNS PTR queries for IP addresses registered as KnownHosts. There are two main goals we followed in developing ZeerHosts:

1. Local hosts inventory with IP/FDQN mapping. This is particular useful for ingesting into Elastic SIEM as ECS `host.*` entries, as it populates Hosts database. Supported by [zeerbit-ecs-pipeline](https://github.com/ZeerBit/zeerbit-ecs-pipeline)
2. Enrichment of `conn.log` with `orig_fqdn` and/or `resp_fqdn` via `conn-add-fqdn.zeek`

## conn-add-fqdn.zeek
Enrichment of `conn.log` with `orig_fqdn` and/or `resp_fqdn`, for IPs in local networks only, using `ZeerHosts` inventory. Mapped into ECS fields `source.domain` and `destination.domain` by [zeerbit-ecs-pipeline](https://github.com/ZeerBit/zeerbit-ecs-pipeline).

## conn-add-geo.zeek
Enrichment of `conn.log` with `orig_geo_*` and/or `resp_geo_*`, for non-local IPs, using standard Zeek `lookup_location` functionality. Mapped into ECS fields `source.geo.*` and `destination.geo.*` by [zeerbit-ecs-pipeline](https://github.com/ZeerBit/zeerbit-ecs-pipeline).
