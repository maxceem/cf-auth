CREATE TABLE `operation` (
	`id` text PRIMARY KEY NOT NULL,
	`kind` text NOT NULL,
	`state` text NOT NULL,
	`opener_user_id` text,
	`opener_credential_id` text,
	`organization_id` text,
	`opener_key` text,
	`request_hash` text NOT NULL,
	`poll_token_hash` text NOT NULL,
	`browser_proof_hash` text,
	`user_code_hash` text,
	`user_code_sealed` text,
	`client_label` text,
	`client_meta` text,
	`loopback_redirect` text,
	`redeem_code_hash` text,
	`outcome` text,
	`sealed_outcome` text,
	`sealed_until` integer,
	`decided_by_user_id` text,
	`payload` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`retain_until` integer NOT NULL,
	FOREIGN KEY (`opener_user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_id`) REFERENCES `organization`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`decided_by_user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE set null,
	CONSTRAINT "operation_state_check" CHECK("operation"."state" in ('pending', 'completed', 'denied', 'expired', 'retired'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `operation_poll_token_hash_unique` ON `operation` (`poll_token_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `operation_user_code_pending_unique` ON `operation` (`user_code_hash`) WHERE "operation"."state" = 'pending';--> statement-breakpoint
CREATE INDEX `idx_operation_organization` ON `operation` (`organization_id`,`state`,`expires_at`);--> statement-breakpoint
CREATE INDEX `idx_operation_opener` ON `operation` (`opener_key`,`state`,`expires_at`);--> statement-breakpoint
CREATE INDEX `idx_operation_state_expires` ON `operation` (`state`,`expires_at`);--> statement-breakpoint
CREATE INDEX `idx_operation_sealed_until` ON `operation` (`sealed_until`);--> statement-breakpoint
CREATE INDEX `idx_operation_retain_until` ON `operation` (`retain_until`);--> statement-breakpoint
ALTER TABLE `api_key` ADD `source` text DEFAULT 'console' NOT NULL;--> statement-breakpoint
ALTER TABLE `api_key` ADD `label` text;