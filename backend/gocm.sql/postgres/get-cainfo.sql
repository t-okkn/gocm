SELECT
  ca_id,
  password,
  created
FROM t_cainfo
WHERE ca_id = :id;
