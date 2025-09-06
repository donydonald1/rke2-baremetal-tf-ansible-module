output "rancher_bootstrap_password" {
  value     = module.rke2_baremetal_tf_ansible.rancher_bootstrap_password
  sensitive = true
}

output "vault_root_token" {
  value     = module.k8s.vault_root_token
  sensitive = true

}
