SELECT
  ca_id,
  serial,
  common_name,
  private_key,
  cert_type,
  cert_data,
  created,
  expiration_date,
  is_revoked,
  revoked
FROM t_certificate
WHERE ca_id = :id
FOR UPDATE;
