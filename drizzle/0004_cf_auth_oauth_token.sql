CREATE TABLE `oauth_token` (
	`id` text PRIMARY KEY NOT NULL,
	`api_key_id` text NOT NULL,
	`generation` integer NOT NULL,
	`access_token_hash` text NOT NULL,
	`access_expires_at` integer NOT NULL,
	`refresh_token_hash` text NOT NULL,
	`rotated_at` integer,
	`sealed_response` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`api_key_id`) REFERENCES `api_key`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_token_access_token_hash_unique` ON `oauth_token` (`access_token_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_token_refresh_token_hash_unique` ON `oauth_token` (`refresh_token_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_token_api_key_id_generation_unique` ON `oauth_token` (`api_key_id`,`generation`);--> statement-breakpoint
ALTER TABLE `api_key` ADD `client_id` text;--> statement-breakpoint
ALTER TABLE `api_key` ADD `resource` text;