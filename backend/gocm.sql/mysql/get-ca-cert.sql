SELECT
  `ca_id`,
  `serial`,
  `common_name`,
  `private_key`,
  `cert_type`,
  `cert_data`,
  `created`,
  `expiration_date`,
  `is_revoked`,
  `revoked`
FROM T_CERTIFICATE
WHERE `ca_id` = :id
  AND `cert_type` = 'CA'
  AND `is_revoked` = b'0'
  AND STR_TO_DATE(`expiration_date`,'%Y-%m-%dT%H:%i:%s') >= NOW();