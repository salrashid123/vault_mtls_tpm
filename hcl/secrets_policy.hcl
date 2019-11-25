path "kv" {                                                                                                                                                 
    capabilities = ["list"]                                                                                                                                  
}                                                                                                                                                            
                                                                                                                                                             
path "kv/data/message" {
    capabilities = ["create", "update", "delete", "list", "read"]
}

path "auth/approle/role/observatory/secret-id" {
  capabilities = ["read", "create", "update", "list"]
}

path "gcp/token/my-token-roleset" {
    capabilities = ["read"]
}

path "gcp/roleset/my-key-roleset" {
    capabilities = ["read"]
}

path "gcpkms/encrypt/my-vault-key" {
    capabilities = [ "update"]
}
 
path "gcpkms/decrypt/my-vault-key" {
    capabilities = [ "update"]
}
 
path "transit/keys/foo" {
  capabilities = ["create", "read"]
}

path "transit/encrypt/foo" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/foo" {
  capabilities = ["create", "update"]
}