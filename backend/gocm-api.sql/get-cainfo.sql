SELECT
  `id`,
  `password`,
  `created`
FROM T_CAINFO
WHERE `id` = :id;