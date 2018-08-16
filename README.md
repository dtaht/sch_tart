This is a fork of sch_cake, intended to get the best possible 
performance for inbound shaping, ripping out all the features
it accumulated over the years.

When the sch_cake project started, all I needed was an inbound
shaper that could crack 100mbits on mips hardware. htb+fq_codel
clocked in at 60mbits. An early version of cake did 100mbits.

I deployed that early version.

Most of my deployed hardware is doing inbound shaping at 100mbits.

finally, cake was done, having sprouted a zillion extra features
... and it couldn't shape 50mbits on the same
hardware, and thus I couldn't deploy the latest and greatest stuff.

This is nothing against the cake team, I'm the only one there that
needs a fast inbound shaper on crappy hardware.

So "tart" is an attempt to fix all that, coded in frustration, from
that last "good, fast" version of cake I had.

Tart is opinionated. It doesn't allow for setting flows, targets,
anything other than bandwidth. Absolutely everything unneeded to
the task of inbound shaping well is ripped out.

It has no stats. It doesn't even try to take a hash if none is present.

And I hope it will scale to 120mbits.

It doesn't compile yet.
