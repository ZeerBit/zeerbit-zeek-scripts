# zeerbit-zeek-scripts
A collection of Zeek customization scripts

## zeer-hosts.zeek
ZeerHosts (`zeer_hosts.log`) is an enriched version of KnownHosts (`known_hosts.log`), with FQDN information collected via DNS PTR queries for IP addresses registered as KnownHosts. There are two main goals we followed in developing ZeerHosts:

1. Local hosts inventory with IP/FDQN mapping. This is particular useful for ingesting into Elastic SIEM as ECS `host.*` entries, as it populates Hosts database. Supported by [zeerbit-ecs-pipeline](https://github.com/ZeerBit/zeerbit-ecs-pipeline)
2. Enrichment of `conn.log` with `orig_fqdn` and/or `resp_fqdn` via `conn-add-fqdn.zeek`

KnownHosts is a requirement for ZeerHosts policy to work. Make sure to load both in your `local.zeek`:

    sudo cat >> `zeek-config --site_dir`/local.zeek << EOF
    #
    # Hosts inventory
    # KnownHosts is a pre-requisite for ZeerHosts
    @load policy/protocols/conn/known-hosts
    # ZeerHosts is version of KnownHosts enriched by FQDN for each host IP
    @load zeerbit-zeek-scripts/zeer-hosts
    EOF

By default, ZeerHosts inventory, as well as KnownHosts, doesn't persist between Zeek restarts. To make it persistent, add the following to you local site policy. This will make sure ZeerHosts and KnownHosts record expiration times are the same between Zeek restarts.

    sudo cat >> `zeek-config --site_dir`/local.zeek << EOF
    # Making hosts inventories persistent
    redef Cluster::stores += {
      [Known::host_store_name]     = Cluster::StoreInfo($backend = Broker::SQLITE),
      [ZeerHosts::host_store_name] = Cluster::StoreInfo($backend = Broker::SQLITE)
    };
    EOF

## conn-add-fqdn.zeek
Enrichment of `conn.log` with `orig_fqdn` and/or `resp_fqdn`, for IPs in local networks only, using `ZeerHosts` inventory. Mapped into ECS fields `source.domain` and `destination.domain` by [zeerbit-ecs-pipeline](https://github.com/ZeerBit/zeerbit-ecs-pipeline).

    sudo cat >> `zeek-config --site_dir`/local.zeek << EOF
    #
    # Enrich conn.log with FQDN information from ZeerHosts inventory
    @load zeerbit-zeek-scripts/conn-add-fqdn
    EOF

## conn-add-geo.zeek
Enrichment of `conn.log` with `orig_geo_*` and/or `resp_geo_*`, for non-local IPs, using standard Zeek `lookup_location` functionality. Mapped into ECS fields `source.geo.*` and `destination.geo.*` by [zeerbit-ecs-pipeline](https://github.com/ZeerBit/zeerbit-ecs-pipeline).

    sudo cat >> `zeek-config --site_dir`/local.zeek << EOF
    #
    # Enrich conn.log with GEO information for non-local IPs
    @load zeerbit-zeek-scripts/conn-add-geo
    EOF
