# Mount the AppRole auth method
#path "sys/auth/approle" {
#  capabilities = [ "create", "read", "update", "delete", "sudo" ]
#}

# Configure the AppRole auth method
#path "sys/auth/approle/*" {
#  capabilities = [ "create", "read", "update", "delete" ]
#}

# Create and manage roles
path "auth/approle/*" {
  capabilities = [ "read" ]
}

# Create and manage roles
#path "auth/approle/*" {
#  capabilities = [ "create", "read", "update", "delete", "list" ]
#}

# Write ACL policies
#path "sys/policy/*" {
#  capabilities = [ "create", "read", "update", "delete", "list" ]
#}

# Enable transit secrets engine
path "sys/mounts/transit" {
  capabilities = [ "read", "update", "delete", "list" ]
}

# To read enabled secrets engines
path "sys/mounts" {
  capabilities = [ "create", "read", "update", "delete" ]
}

# Manage the transit secrets engine
path "transit/*" {
  capabilities = [ "create", "read", "update", "list" ]
}

#Manage the cubbyhole secrets engine
path "cubbyhole/*" {
  capabilities = [ "create", "read", "update", "list" ]
}
