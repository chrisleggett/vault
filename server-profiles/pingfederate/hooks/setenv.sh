#!/bin/sh

export VAULT_TOKEN=$(grep 'Initial Root Token:' /Users/cleggett/Projects/devops/demos/vault/volumes/_data/keys.txt | awk '{print substr($NF, 1, length($NF))}')
