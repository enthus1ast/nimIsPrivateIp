import ../../src/isPrivateIp

doAssert isPrivate("10.0.0.0") == true
doAssert isPrivate("10.255.255.255") == true

doAssert isPrivate("192.168.0.0") == true
doAssert isPrivate("192.168.255.255") == true

doAssert isPrivate("172.16.0.0") == true
doAssert isPrivate("172.31.255.255") == true
doAssert isPrivate("172.15.255.255") == false
doAssert isPrivate("172.32.0.0") == false

doAssert isPrivate("127.0.0.0") == true
doAssert isPrivate("127.255.255.255") == true

doAssert isPrivate("169.254.0.0") == true
doAssert isPrivate("169.254.255.255") == true

doAssert isPrivate("8.8.8.8") == false

# ipv6 (its a mess...)
doAssert isPrivate("::1") == true
doAssert isPrivate("::") == true # TODO not sure

doAssert isPrivate("::192.168.2.128") == true # handle this case even it its depricated
doAssert isPrivate("::127.0.0.1") == true # handle this case even it its depricated

# ::ffff:0.0.0.0  <-> ::ffff:255.255.255.255 # IPv4 mapped addresses.
doAssert isPrivate("::ffff:192.168.2.128") == true

# ::ffff:0:0.0.0.0 <-> ::ffff:0:255.255.255.255 # IPv4 translated addresses. (WHAT?!)
doAssert isPrivate("::ffff:0:192.168.2.128") == true

# 64:ff9b::0.0.0.0 <-> 64:ff9b::255.255.255.255	 # IPv4/IPv6 translation. (WHAT2 ?!?)
doAssert isPrivate("64:ff9b::192.168.2.128") == true

# Unique local address
doAssert isPrivate("fc00::") == true
doAssert isPrivate("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == true

# Link-local address
doAssert isPrivate("fe80::") == true
doAssert isPrivate("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == true

# ORCHIDv2
doAssert isPrivate("2001:20::") == true
doAssert isPrivate("2001:2f:ffff:ffff:ffff:ffff:ffff:ffff") == true



