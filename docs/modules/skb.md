# SKB collector

The `skb` collector provides insights into the `struct sk_buff` (we call
instances of this `skb` below) kernel data structure, which holds metadata and
data for networking packets.

The `skb` collector do not install any probe itself, and is only responsible for
gathering data whenever an `skb` is available in a probe arguments. This is done
automatically. Eg. if the `skb` collector is enabled and a probe is added
(manually, by a profile or by another collector) on `kfree_skb_reason`, the
`skb` collector will generate events with data coming from the `skb` given as an
argument to the `kfree_skb_reason` function.

## Arguments

The `skb` collector has a single specific argument, `--skb-sections`. This is
used to choose which parts of the `skb` metadata and/or data to retrieve and
export in the events.

A special section, `packet`, can be used to dump the packet itself, unparsed.
It's best used in combination with the `dev` and `ns` sections, and can later be
converted to a `pcap-ng` file for post-processing using external tools.

## Events

Full `skb` collector events will be constructed with the following. Non-reported
or invalid fields are automatically hidden.

### Ns event section

```none
ns {namespace id}
```

### Net device event section

```none
if {interface index} ({interface name}) rxif {rx interface index}
```

### Ethernet section

```none
{src mac} > {dst mac} ethertype {etype name} ({etype hex})
```

### ARP section

```none
request who-has {ip} tell {ip}
```

or,

```none
reply {ip} is at {mac}
```

### IP section

For IPv4:

```none
{src ip}.{src port} > {dst ip}.{dst port} {ECN info} ttl {ttl} tos {tos} id {id}
    off {frag offset} [{flags}] len {packet len} proto {protocol name}
```

- `ECN info` can be one of `CE`, `ECT(0)` or `ECT(1)`.
- `flags` are constructed with a combination of `+`, `DF` and `rsvd`.

For IPv6:

```none
{src ip}.{src port} > {dst ip}.{dst port} {ECN info} ttl {ttl} label {flow label}
    len {packet len} proto {protocol name}
```

### TCP section

```none
flags [{flags}] seq {sequence} ack {acked sequence} win {window}
```

- `flags` are constructed using a combination of `F` (fin), `S` (syn), `R`
  (reset), `P` (push), `.` (ack), `U` (urgent).
- `sequence` can be a range (`{start}:{end}`) or a single number (`{sequence}`).

### UDP section

```none
len {UDP data len}
```

# ICMP section

```none
type {type number} code {code number}
```

### Metadata & dataref sections

Those two sections report metadata and reference counting from the socket buffer
itself.

```none
skb [csum {packet checksum} hash {skb hash} data_len {skb data lenght} priority {skb priority}
    {flags} fclone {fast clone count} users {user count} dataref {skb refcount}]
```

- `flags` are a combination of `nohdr` and `cloned`.

