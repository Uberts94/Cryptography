# Exercise form: https://docs.google.com/forms/d/e/1FAIpQLSckv7IYOXzDv_uQfdrV0wRA4K9gGm1cwpEeKQBCmzCOnY8qVQ/formResponse
# Followed: https://github.com/aldobas/cryptography-03lpyov-exercises/tree/master/AY2223/Python/basics

# Write a piece of code that computes the HMAC-SHA384 of a string (string_to_hash).

from mykeys import key
from mydata_ex import string_hmac

from Crypto.Hash import HMAC, SHA384

mac_generator = HMAC.new(key, digestmod=SHA384)
mac_generator.update(string_hmac)
mac = mac_generator.hexdigest()

# print the HMAC as an hexstring
print(mac)

##########################################################################
# Verifying HMAC-SHA384
# hmac_ver = HMAC.new(key, digestmod=SHA384)
# hmac_ver.update(string_hmac)

# try:
#     hmac_ver.hexverify(mac)
#     print("Verified")
# except ValueError:
#     print("Wrong secret or message")