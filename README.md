# coraldpi

I want to capture an overview of my lan from an rpi5 that acts like a router
but there is no good ways to do that so I made this to address the lack of
such monitoring tools.

For now scoped to only ipv4 and only "common" things like stuff on top of tcp and udp.

It needs to:
- capture on an interface (done)
- track conversations between ips (done)
- reassemble tcp streams
- ship the events outside of router to the storage/analysis server

## coraldpi-ux server

Said storage/analysis server should be able to effectvely:
- expose a web ui
- show live ingested events from the capturer
- store finished conversations somewhere (duckdb?)
- visualise historical data from storage
- neat graphs charts idk
