SELECT
  COALESCE(MAX(serial), 0)
FROM t_certificate
WHERE ca_id = :id;
