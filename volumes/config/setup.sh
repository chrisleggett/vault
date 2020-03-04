#!/bin/sh

## Start up ol' vault
echo "[*] Initialize the vault..."
nohup vault server -config=/vault/config/vault.json &

echo "sleeping..."
sleep 5

## CONFIG LOCAL ENV
echo "[*] Config local environment..."
alias vault='vault "$@"'
export VAULT_ADDR=https://vault:8200
export VAULT_CACERT=/vault/config/vault_public.pem

## INIT VAULT
echo "[*] Init vault..."
vault operator init -address=${VAULT_ADDR} > /data/keys.txt
export VAULT_TOKEN=$(grep 'Initial Root Token:' /data/keys.txt | awk '{print substr($NF, 1, length($NF))}')

## UNSEAL VAULT
echo "[*] Unseal vault..."
vault operator unseal -address=${VAULT_ADDR} $(grep 'Key 1:' /data/keys.txt | awk '{print $NF}')
vault operator unseal -address=${VAULT_ADDR} $(grep 'Key 2:' /data/keys.txt | awk '{print $NF}')
vault operator unseal -address=${VAULT_ADDR} $(grep 'Key 3:' /data/keys.txt | awk '{print $NF}')

## Login
echo "[*] Login..."
echo "[*] Vault Token: "${VAULT_TOKEN}
vault login ${VAULT_TOKEN}

## Enable AppRole Auth
echo "[*] Enable AppRole Authentication"
vault auth enable approle

## Enable KV-2 Secrets Engine
echo "[*] Enable kv-v2 secrets engine"
vault secrets enable -version=2 kv

#Enable Transit
echo "[*] Enable Transit..."
vault secrets enable transit

## SET transit policy
echo "[*] Set Transit and Secrets Policy..."
vault policy write transit /vault/config/transit-policy.hcl

## SET pingfederate policy
echo "[*] Set Pingfederate Policy..."
vault policy write pingfederate /vault/config/pingfederate-policy.hcl

## Generate token from PingFederate Policy
#echo "[*] Generating wrapping token to be used by PingFederate..."
#echo "[*] This token is valid for 120 seconds..."
#vault token create -policy=pingfederate -wrap-ttl=120 > /data/pingfederate_wrapped_token.txt

## SET pingfederate policy
echo "[*] Set Pingfederate Policy..."
vault policy write pingfederate /vault/config/pingfederate-policy.hcl

## Create Named Role 
echo "[*] Create Named Role"
echo $PINGFEDERATE_SUBNET_CIDR
vault write auth/approle/role/pingfederate policies=pingfederate bind_secret_id=false secret_id_bound_cidrs=$PINGFEDERATE_SUBNET_CIDR

## Get the Role ids
echo "[*] Retrieve the role id"
vault read auth/approle/role/pingfederate/role-id > /data/pingfederate_role_id.txt

#echo "[*] Doing something insane here!!"
#vault write auth/approle/login role_id=$(vault read -field=role_id auth/approle/role/pingfederate/role-id)

wait ${!}   