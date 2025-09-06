module "rke2_baremetal_tf_ansible" {
  source = "git::https://github.com/donydonald1/rke2-baremetal-tf-ansible.git"
  #   source                                = "../rke2-baremetal-tf-ansible/"
  baremetal_servers                     = var.baremetal_servers
  private_registry_url                  = var.private_registry_url
  private_registry_password             = var.private_registry_password
  private_registry_username             = var.private_registry_username
  private_registry_insecure_skip_verify = var.private_registry_insecure_skip_verify
  dockerhub_registry_auth_username      = var.dockerhub_registry_auth_username
  dockerhub_registry_auth_password      = var.dockerhub_registry_auth_password
  ssh_private_key_file                  = var.ssh_private_key_file
  manager_rke2_api_dns                  = var.manager_rke2_api_dns
  manager_rke2_api_ip                   = var.manager_rke2_api_ip
  manager_rke2_loadbalancer_ip_range    = var.manager_rke2_loadbalancer_ip_range
  rke2_version                          = var.rke2_version
  cluster_name                          = var.cluster_name
  kube-vip-nginx-lb-ip                  = var.kube-vip-nginx-lb-ip
  enable_kube-vip-lb                    = true
  domain                                = var.domain
  cloudflare_account_id                 = var.cloudflare_account_id
  cloudflare_api_key                    = var.cloudflare_api_key
  cloudflare_email                      = var.cloudflare_email
  rancher_bootstrap_password            = var.rancher_bootstrap_password
  argocd_hostname                       = var.argocd_hostname
  argocd_admin_password                 = var.argocd_admin_password
  argocd_github_app_id                  = var.argocd_github_app_id
  argocd_github_app_installation_id     = var.argocd_github_app_installation_id
  argocd_iodc_issuer_url                = var.argocd_iodc_issuer_url
  argocd_oidc_client_id                 = var.argocd_oidc_client_id
  argocd_oidc_client_secret             = var.argocd_oidc_client_secret
  argocd_project_names                  = var.argocd_project_names
  argocd_tamplate_repo_url              = var.argocd_tamplate_repo_url
  argocd_github_app_private_key         = var.argocd_github_app_private_key
  rancher_hostname                      = var.rancher_hostname
  create_kubeconfig                     = var.create_kubeconfig
  enable_rancher                        = var.enable_rancher
  enable_external_dns                   = true
  enable_external_secrets               = true
  enable_argocd                         = true
  vault_oidc_discovery_url              = var.vault_oidc_discovery_url
  vault_oidc_client_id                  = var.vault_oidc_client_id
  vault_oidc_client_secret              = var.vault_oidc_client_secret
  enable_longhorn                       = false
  vault_secrets                         = var.vault_secrets
  s3_backup_endpoint                    = var.s3_backup_endpoint
  s3_backup_access_key                  = var.s3_backup_access_key
  s3_backup_secret_key                  = var.s3_backup_secret_key
  s3_backup_bucketname                  = var.s3_backup_bucketname
  snapshot_name                         = var.snapshot_name
  s3_backup_skip_ssl_verify             = var.s3_backup_skip_ssl_verify
}

module "cloudflare" {
  source                 = "git::https://github.com/donydonald1/rke2-baremetal-tf-ansible.git//modules/cloudflare"
  cloudflare_tunnel_name = module.rke2_baremetal_tf_ansible.cluster_name
  cloudflare_account_id  = module.rke2_baremetal_tf_ansible.cloudflare_account_id
  cloudflare_zone        = module.rke2_baremetal_tf_ansible.domain_name
}

module "helm" {
  source       = "git::https://github.com/donydonald1/rke2-baremetal-tf-ansible.git//modules/helm"
  cluster_name = module.rke2_baremetal_tf_ansible.cluster_name
  domain       = module.rke2_baremetal_tf_ansible.domain_name
  depends_on   = [module.cloudflare, module.rke2_baremetal_tf_ansible]
}

module "k8s" {
  source                    = "git::https://github.com/donydonald1/rke2-baremetal-tf-ansible.git//modules/kubernetes"
  cluster_name              = module.rke2_baremetal_tf_ansible.cluster_name
  cloudflare_account_id     = module.rke2_baremetal_tf_ansible.cloudflare_account_id
  tunnel_id                 = module.cloudflare.tunnel_id
  tunnel_id_random_password = module.cloudflare.tunnel_id_random_password
  cert_manager_issuer_token = module.cloudflare.cert_manager_issuer_token
  cloudflare_api_token      = module.cloudflare.cloudflare_api_token
  vault_admin_password      = var.vault_admin_password
  vault_admin_username      = var.vault_admin_username
  domain                    = module.rke2_baremetal_tf_ansible.domain_name
  vault_hostname            = var.vault_hostname
  argocd_repo_url           = var.argocd_tamplate_repo_url
  vault_oidc_discovery_url  = var.vault_oidc_discovery_url
  vault_organization        = var.vault_organization
  vault_oidc_client_id      = var.vault_oidc_client_id
  vault_oidc_client_secret  = var.vault_oidc_client_secret
  depends_on                = [module.cloudflare, module.rke2_baremetal_tf_ansible, module.helm]
}

module "vault" {
  source        = "git::https://github.com/donydonald1/rke2-baremetal-tf-ansible.git//modules/vault"
  vault_secrets = var.vault_secrets
  depends_on    = [module.k8s, module.rke2_baremetal_tf_ansible]
}

resource "rancher2_bootstrap" "admin" {
  provider         = rancher2.bootstrap
  initial_password = module.rke2_baremetal_tf_ansible.rancher_bootstrap_password
  password         = var.rancher_admin_password

  token_update = false
  lifecycle {
    ignore_changes = [
      password,
      initial_password,
      token_update,
    ]

  }
  depends_on = [module.rke2_baremetal_tf_ansible]
}

resource "rancher2_project" "ci_cd_projects" {
  provider         = rancher2.admin
  for_each         = var.rancher_projects
  name             = each.value.name
  description      = each.value.description
  wait_for_cluster = true
  cluster_id       = each.value.cluster_id
}

resource "rancher2_app_v2" "cis_benchmark_rancher" {
  provider   = rancher2.admin
  cluster_id = "local"
  name       = "rancher-cis-benchmark"
  namespace  = "cis-operator-system"
  repo_name  = "rancher-charts"
  chart_name = "rancher-cis-benchmark"
  depends_on = [rancher2_bootstrap.admin]
}

resource "rancher2_app_v2" "rancher_compliance" {
  provider      = rancher2.admin
  chart_name    = "rancher-compliance"
  cluster_id    = "local"
  name          = "rancher-compliance"
  namespace     = "cis-operator-system"
  repo_name     = "rancher-charts"
  force_upgrade = false
  wait          = false
  values        = <<EOF
affinity: {}
alerts:
    enabled: true
    metricsPort: 8080
    severity: warning
debug: null
global:
cattle:
    clusterName: local
    EOF
  depends_on    = [rancher2_bootstrap.admin]
}
