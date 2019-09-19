# CertManagement
Improved certificate management by allowing external java keystore to be used as certificates repository by the
Gateway instead or in addition with the internat CertStore.

Offer capability of searching certificate by different key type : 
> by alias
> by x5ts Thumbprint
> by distinguish name
> by sha1 fingerprint

Updating certificates without any restart using a cleaning service : you can change/update your keystore and then force reloading certificates without service interruption. 

Using a cache for performance reasons: the keystore file is accessed only once.
