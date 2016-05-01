Group 5 Project 3


Extra Feature - ACL
================
ACLs are enabled by default. If this turns out to be a problem, you can
deactivate them in the megaswitch.py file with
`self.ACL_FEATURE_ENABLED = False`

From the pox/ext directory, you can send some ACLs to the pox controller with 
the acl utility.
`../../acls/acl_util.py aclfile 127.0.0.1`

This will cause the controller to update all the flows on the switches
and drop traffic that does not match a rule. 

This is implemented in the `_connection_is_permitted` method of megaswitch.py