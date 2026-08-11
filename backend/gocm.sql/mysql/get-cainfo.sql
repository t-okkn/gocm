SELECT
  `ca_id`,
  `password`,
  `created`
FROM T_CAINFO
WHERE `ca_id` = :id;