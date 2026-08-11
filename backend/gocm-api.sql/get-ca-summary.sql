SELECT
  `ca_id`,
  `serial`,
  `common_name`,
  `cert_type`,
  `created`,
  `expiration_date`,
  CAST(`is_revoked` AS UNSIGNED) AS `is_revoked`,
  `revoked`
FROM T_CERTIFICATE
WHERE `ca_id` = :id;