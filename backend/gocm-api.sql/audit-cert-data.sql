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
WHERE `ca_id` = :id
  AND CAST(`is_revoked` AS UNSIGNED) = 0
  AND STR_TO_DATE(`expiration_date`,'%Y-%m-%dT%H:%i:%s') >= NOW();