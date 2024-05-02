dovecot = {
    ["auth"] = {
        ["PASSDB_RESULT_USER_DISABLED"] = "dovecot.auth.PASSDB_RESULT_USER_DISABLED",
        ["PASSDB_RESULT_INTERNAL_FAILURE"] = "dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE",
        ["PASSDB_RESULT_NEXT"] = "dovecot.auth.PASSDB_RESULT_NEXT"
    },
    ["i_info"] = print,
    ["i_warning"] = print
}

require "login"

print(auth_passdb_lookup({remote_ip = '172.17.1.204', user = 'honey', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '109.42.242.226', user = 'honey-blue-andr', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '139.162.133.252', user = 'honey-sugar', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '162.120.146.160', user = 'honey-all-ai', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '162.120.146.160', user = 'honey-fairmail', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '172.17.3.145', user = 'honey-samsung', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '172.17.3.18', user = 'honey-all-ai', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '176.112.169.192', user = 'honey-craig', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '18.209.23.233', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '18.212.244.38', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '18.234.131.58', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '18.234.232.163', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '188.93.56.121', user = 'honey-mru', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '188.93.56.124', user = 'honey-craig2', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '3.140.37.101', user = 'honey', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '34.207.207.108', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '34.207.209.64', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '3.80.87.194', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '3.88.42.55', user = 'honey', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '3.95.204.151', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '44.199.102.47', user = 'honey-newton', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '50.17.99.17', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '52.23.158.188', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '52.97.246.245', user = 'honey-outlook-new-win', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '54.144.102.108', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '54.147.29.115', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '54.196.248.129', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '54.198.158.192', user = 'honey', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '54.209.145.83', user = 'honey-edison', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '54.90.94.70', user = 'honey-newton', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '80.136.49.97', user = 'honey-samsung', service = 'imap'}))
print(auth_passdb_lookup({remote_ip = '93.212.136.168', user = 'honey-samsung', service = 'imap'}))