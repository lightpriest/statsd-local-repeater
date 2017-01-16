statsd-local-repeater
=====================

A small utility that sniffs UDP packets and re-sends them to a different
target. It was mainly built for using with statsd.

It works by listening with `pcap` (tcpdump) to incoming packets. By default
it'll sniff with the filter `udp and dst host 127.0.0.1 and port 8125` and
send everything to `127.0.0.1:8126`. The hosts and ports can be modified
but UDP is hard-coded.

Why?
----

This was created out of the need to have a completely different telemetry
pipeline beginning from the instances/agents. For example, if you're
using datadog's agent and want to have another (e.g. telegraf) agent
that will receive the same statsd data, but won't be affected from
datadog's agent internal aggregations, you can run another statsd agent
on a different port and redirect the stream of data to it.

Additionally, you don't have to make any modifications to your
current application stack. Everything continues to work as it is.

Using
-----

```
git clone git@github.com:lightpriest/statsd-local-repeater.git
cd statsd-local-repeater
make
sudo ./statsd-local-repeater # sudo required for pcap/tcpdump
```
