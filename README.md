# TinyCS_Proto
Tiny Cyberspace prototype implementation.

A very simple, small, flat, but multi-user, cyberspace implementation.

I respect to 
+ https://github.com/arkin0x/ONOSENDAI
+ https://github.com/arkin0x/cyberspace

In the future, I would like to support the cyberspace meta protocol.


## Protocol
### kind 29420 : User Position
content
```
{"x": "0", "y": "0", "z": "0", "v": ["TinyCS", "1.0.0"]}
```

Indicates the current position of the user. All integers.
Consists of X,Z planes and a Y layer.
ver is the protocol version.

The location information is updated once every 10 seconds when there is a change position, or when the user posts something kind1.
To prevent relay load, it should not be updated at high frequency.
