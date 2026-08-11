SELECT
  `ca_id`,
  `serial`,
  `common_name`,
  `private_key`,
  `cert_type`,
  `cert_data`,
  `created`,
  `expiration_date`,
  CAST(`is_revoked` AS UNSIGNED) AS `is_revoked`,
  `revoked`
FROM `T_CERTIFICATE`
WHERE `ca_id` = :id
FOR UPDATE;