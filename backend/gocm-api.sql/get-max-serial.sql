SELECT
  MAX(`serial`)
FROM T_CERTIFICATE
WHERE `ca_id` = :id;