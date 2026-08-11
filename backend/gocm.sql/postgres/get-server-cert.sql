SELECT
  ca_id,
  serial,
  common_name,
  private_key,
  cert_type,
  cert_data,
  created,
  expiration_date,
  is_revoked::int AS is_revoked,
  revoked
FROM T_CERTIFICATE
WHERE ca_id = :id
  AND cert_type = 'SERVER'
  {{if ne .Serial 0 -}}
  AND serial = :serial
  {{- end}}
  {{if ne .CommonName "" -}}
  AND common_name = :common_name
  {{- end}}
  AND is_revoked = FALSE
  AND expiration_date::timestamp >= CURRENT_TIMESTAMP;
