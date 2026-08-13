SELECT
  ca_id,
  serial,
  common_name,
  cert_type,
  created,
  expiration_date,
  is_revoked,
  revoked
FROM t_certificate
WHERE ca_id = :id
  AND is_revoked = FALSE
  AND expiration_date::timestamp >= CURRENT_TIMESTAMP;
