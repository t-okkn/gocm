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
WHERE ca_id = :id;
