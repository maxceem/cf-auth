-- cf-auth 1.0 drops unclaimed accounts. An organization still waiting to be
-- claimed (it has a deadline and no human owner) is removed with everything
-- that belongs to it, before its deadline column goes: without the deadline,
-- its keys would sign in again. Children are deleted explicitly, in order,
-- so nothing is left behind whether or not foreign keys are enforced.
DELETE FROM `oauth_token` WHERE `api_key_id` IN (SELECT `id` FROM `api_key` WHERE `organization_id` IN (SELECT `o`.`id` FROM `organization` AS `o` WHERE `o`.`expires_at` IS NOT NULL AND NOT EXISTS (SELECT 1 FROM `organization_user` AS `m` JOIN `user` AS `u` ON `u`.`id` = `m`.`user_id` WHERE `m`.`organization_id` = `o`.`id` AND `m`.`role` = 'owner' AND `u`.`kind` = 'human')));--> statement-breakpoint
DELETE FROM `api_key` WHERE `organization_id` IN (SELECT `o`.`id` FROM `organization` AS `o` WHERE `o`.`expires_at` IS NOT NULL AND NOT EXISTS (SELECT 1 FROM `organization_user` AS `m` JOIN `user` AS `u` ON `u`.`id` = `m`.`user_id` WHERE `m`.`organization_id` = `o`.`id` AND `m`.`role` = 'owner' AND `u`.`kind` = 'human'));--> statement-breakpoint
DELETE FROM `operation` WHERE `organization_id` IN (SELECT `o`.`id` FROM `organization` AS `o` WHERE `o`.`expires_at` IS NOT NULL AND NOT EXISTS (SELECT 1 FROM `organization_user` AS `m` JOIN `user` AS `u` ON `u`.`id` = `m`.`user_id` WHERE `m`.`organization_id` = `o`.`id` AND `m`.`role` = 'owner' AND `u`.`kind` = 'human'));--> statement-breakpoint
DELETE FROM `organization_invitation` WHERE `organization_id` IN (SELECT `o`.`id` FROM `organization` AS `o` WHERE `o`.`expires_at` IS NOT NULL AND NOT EXISTS (SELECT 1 FROM `organization_user` AS `m` JOIN `user` AS `u` ON `u`.`id` = `m`.`user_id` WHERE `m`.`organization_id` = `o`.`id` AND `m`.`role` = 'owner' AND `u`.`kind` = 'human'));--> statement-breakpoint
DELETE FROM `organization_user` WHERE `organization_id` IN (SELECT `o`.`id` FROM `organization` AS `o` WHERE `o`.`expires_at` IS NOT NULL AND NOT EXISTS (SELECT 1 FROM `organization_user` AS `m` JOIN `user` AS `u` ON `u`.`id` = `m`.`user_id` WHERE `m`.`organization_id` = `o`.`id` AND `m`.`role` = 'owner' AND `u`.`kind` = 'human'));--> statement-breakpoint
DELETE FROM `organization` WHERE `expires_at` IS NOT NULL AND NOT EXISTS (SELECT 1 FROM `organization_user` AS `m` JOIN `user` AS `u` ON `u`.`id` = `m`.`user_id` WHERE `m`.`organization_id` = `organization`.`id` AND `m`.`role` = 'owner' AND `u`.`kind` = 'human');--> statement-breakpoint
ALTER TABLE `operation` DROP COLUMN `loopback_redirect`;--> statement-breakpoint
ALTER TABLE `operation` DROP COLUMN `redeem_code_hash`;--> statement-breakpoint
ALTER TABLE `organization` DROP COLUMN `expires_at`;
