Test if an ip address is private.
Does also check if an IPv4 address was encapsulated into IPv6

```nim
import isPrivateIp
doAssert isPrivate("192.168.1.1") == true
doAssert isPrivate("64:ff9b::192.168.2.128") == true
doAssert isPrivate("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == true
```

