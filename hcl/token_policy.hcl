
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew" {
  capabilities = ["update", "create"]
}

path "auth/token/lookup-accessor" {
  capabilities = [ "read", "update" ]
}

