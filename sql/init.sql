DROP TABLE IF EXISTS `tc_users`;
CREATE TABLE `tc_users` (
  `id` INTEGER NOT NULL AUTO_INCREMENT,
  `slack_team_id` VARCHAR(256),
  `slack_user_id` VARCHAR(256),
  `slack_user_name` VARCHAR(256),
  `slack_team_name` VARCHAR(256),
  `slack_access_tok` VARCHAR(256),
  `slack_access_scopes` VARCHAR(256),
  PRIMARY KEY(`id`),
  UNIQUE KEY(`slack_team_id`, `slack_user_id`),
  INDEX(`slack_team_id`, `slack_user_id`)
);

DROP TABLE IF EXISTS `tc_worlds`;
CREATE TABLE `tc_worlds` (
  `id` INTEGER NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(64),
  `group_prefix` VARCHAR(32),
  `url` VARCHAR(256),
  `desc` VARCHAR(10240),
  PRIMARY KEY(`id`),
  UNIQUE KEY(`name`),
  UNIQUE KEY(`group_prefix`),
  INDEX(`name`)
);

DROP TABLE IF EXISTS `tc_world_users`;
CREATE TABLE `tc_world_users` (
  `id` INTEGER NOT NULL AUTO_INCREMENT,
  `user_id` INTEGER,
  `world_id` INTEGER,
  `world_user_name` VARCHAR(256),
  `slack_channel_id` VARCHAR(256),
  `status` VARCHAR(32),
  PRIMARY KEY (`id`),
  UNIQUE KEY(`user_id`, `world_id`),
  INDEX(`user_id`),
  INDEX(`world_id`),
  INDEX(`status`)
);

