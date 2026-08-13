SELECT
  COUNT(serial) AS count
FROM t_certificate
WHERE ca_id = :id
  AND cert_type = 'CA';
