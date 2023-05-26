# IPQualityScore IP Reputation Flat File Database Lua Reader
Copyright 2023 IPQualityScore LLC

IPQualityScore offers a single file database engine that provides direct access to a copy of
our entire IP address reputation database for on-premise deployment. The
[proxy detection database](https://www.ipqualityscore.com/proxy-detection-database)
includes anonymous proxies, botnets, VPNs, TOR, and high risk IP addresses. The IPQS
on-premise local database includes data from our
[threat intelligence feeds](https://www.ipqualityscore.com/threat-intelligence-feed-api)
and all data points from our
[IP address reputation API](https://www.ipqualityscore.com/proxy-vpn-tor-detection-service).

This implementation in pure Lua of our flat file database reader provides a simple,
zero-friction interface in the form of several small Lua modules.

## Installation
The `ipqs-db-reader` is available as a "rock" via [LuaRocks](https://luarocks.org/).
```
luarocks install ipqs-db-reader
```
Then, in your Lua source file, simply `require` `ipqs.reader` and `ipqs.record`.

## Reader
### `reader.open (filename)`
Attempts to open the flat file database `filename`, returning an instance of a `reader` on
success, or `nil` and an error message. Pass the reader as the first argument to
`record.fetch` to search the database for a particular address.

### `reader.is_ipv4`
`true` if and only if `reader.open` was successfully called on an IPv4 flat file database

### `reader.is_ipv6`
`true` if and only if `reader.open` was successfully called on an IPv6 flat file database

### `reader.is_blacklist`
`true` if and only if the flat file database is a blacklist file

### `reader.binary_option`
`true` if and only if each record contains additional "binary options" (see below)

## Record
### `record.fetch (reader, ip)`
Searches the database for `ip` and returns a table with the associated record, if one exists,
or `nil` and an error message.

If the exact IP address is not found, then the response depends on whether the database file
is a blacklist file or not. If it is a blacklist file, then the search will return `nil`. If
it is not a blacklist file and the exact IP address is not found, the reader will continue
searching for the associated CIDR block. For example, if the IP address x.y.z.5/24 is not
found but x.y.z.0/24 is, then the record associated with the CIDR block x.y.z.0 address will
be returned.

`reader` must be the table returned by a successful call to `reader.open`. `ip` must be a
properly formatted IPv4 or IPv6 address corresponding to the database type, e.g. "8.8.0.0" or
"2001:4860:4860::8844". For example, passing an IPv6 address as an argument will return nil if
the database file is an IPv4 file.

### `record.abuse_velocity`
How frequently the IP address is engaging in abuse across the IPQS threat network. Values can
be "high", "medium", "low", or "none".

### `record.connection_type`
Classification of the IP address connection type as "Residential", "Corporate", "Education",
"Mobile", "Data Center", or "Unknown".

### `record:get (column)`
Returns the value associated with the column named `column`, if one exists, or `nil` if the
column is not in the record. See the table below for the default columns included in most
files. Your particular file may have columns in addition to the default columns. Speak with
your IPQualityScore representative if you have any questions about your flat file database.

## Default Columns
The values of common default columns may be accessed directly, e.g. `rec.Country`, `rec.City`,
etc. Note that a table returned by `record.fetch` is read-only, so attempting to mutate a
value will cause an error:
`rec.Country = "IN"`
```
--> lua: example.lua:22: attempt to update a read-only table
```
The following fields will be present in most flat file databases:

| Name           | Type     | Description |
|----------------|----------|-------------|
| Country        | String   |             |
| City           | String   |             |
| Region         | String   |             |
| ISP            | String   |             |
| Organization   | String   |             |
| Timezone       | String   |             |
| ASN            | Integer  | Autonomous System Number |
| ZeroFraudScore | Integer  | The "strictness" = 0 fraud score for this IP address[^1] |
| OneFraudScore  | Integer  | The "strictness" = 1 fraud score for this IP address[^1] |
| Latitude[^2]   | Float    |             |
| Longitude[^2]  | Float    |             |

## Binary Options
If your flat file includes additional "Binary Options", the following *boolean* fields will
also be defined. If you are unsure, you can check by evaluating `reader.binary_option`, or by
asking your IPQualityScore representative. You may also wish to review the
[IPQualityScore Proxy and VPN Detection API documentation](https://www.ipqualityscore.com/documentation/proxy-detection/overview)
for additional details about each of these fields.

| Name                  | Description |
|-----------------------|-------------|
| `is_proxy`            | Is this IP address suspected to be a proxy? (SOCKS, Elite, Anonymous, VPN, Tor, etc.) |
| `is_vpn`              | Is this IP suspected of being a VPN connection? This can include data center ranges which can become active VPNs at any time. The "proxy" status will always be true when this value is true. |
| `is_tor`              | Is this IP suspected of being a TOR connection? This can include previously active TOR nodes and exits which can become active TOR exits at any time. The "proxy" status will always be true when this value is true. |
| `is_crawler`          | Is this IP associated with being a confirmed crawler from a mainstream search engine such as Googlebot, Bingbot, Yandex, etc. based on hostname or IP address verification? |
| `recent_abuse`        | Has there been any recently verified abuse across our network for this IP address? Abuse could be a confirmed chargeback, compromised device, fake app install, or similar malicious behavior within the past few days. |
| `is_blacklisted`      | Has the IP been blacklisted by any 3rd party agency for spam, abuse or fraud? |
| `is_private`          | Is the IP a private, non-routable IP address? |
| `is_mobile`           | Is the IP likely owned by a mobile carrier? |
| `has_open_ports`      | Has the IP recently had open (listening) ports? |
| `is_hosting_provider` | Whether the IP is likely owned by a hosting provider or is leased to a hosting company. |
| `active_vpn`          | Identifies active VPN connections used by popular VPN services and private VPN servers. |
| `active_tor`          | Identifies active TOR exits on the TOR network. |
| `public_access_point` | Indicates if this IP is likely to be a public access point such as a coffee shop, college or library. |

[^1]: See [proxy documentation](https://www.ipqualityscore.com/documentation/proxy-detection/overview) for details about strictness.
[^2]: Due to the nature of IEEE-754 floating-point representation, these single-precision
values may display misleading precision. For example, 32.51 when converted to little endian
hexadecimal representation is: `0x3D0A0242`, which if interpreted literally actually
represents 32.509998321533 in Lua. Our Latitude and Longitude values should be interpreted as
accurate to 2 (rounded) decimal places, e.g. `string.format("%.2f", record:get("Latitude"))`
