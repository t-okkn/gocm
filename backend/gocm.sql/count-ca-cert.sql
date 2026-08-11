SELECT
  COUNT(`serial`) AS `count`
FROM T_CERTIFICATE
WHERE `ca_id` = :id
  AND `cert_type` = 'CA';