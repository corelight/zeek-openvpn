
zeek::openvpn
=================================

A plugin to detect and parse OpenVPN in the following modes:

- UDP w/ TLS
- UDP w/ TLS & TLS Auth
- TCP w/ TLS
- TCP w/ TLS & TLS Auth

So far this will not detect shared key mode for UDP or TCP.

If you have zkg and you have already run...

```
zkg autoconfig
```

... then you can install this package as so:

```
sudo zkg install zeek-openvpn
```

Now in any Zeek script, just load the plugin and it "just works":

```
@load Zeek/OpenVPN
```

New events for this plugin are found in [events.bif](src/events.bif).