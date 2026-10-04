-- name: GetAppAccessDomainSettings :one
SELECT portal_url, app_base_domain, version FROM app_access_domain_settings WHERE singleton;
