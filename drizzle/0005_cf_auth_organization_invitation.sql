CREATE TABLE `organization_invitation` (
	`id` text PRIMARY KEY NOT NULL,
	`organization_id` text NOT NULL,
	`email` text NOT NULL,
	`role` text NOT NULL,
	`token_hash` text NOT NULL,
	`invited_by_user_id` text,
	`created_at` text NOT NULL,
	`expires_at` text NOT NULL,
	`response` text,
	`responded_at` text,
	`responded_by_user_id` text,
	FOREIGN KEY (`organization_id`) REFERENCES `organization`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`invited_by_user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`responded_by_user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE set null,
	CONSTRAINT "organization_invitation_role_check" CHECK("organization_invitation"."role" in ('owner', 'admin', 'member')),
	CONSTRAINT "organization_invitation_response_check" CHECK("organization_invitation"."response" is null or "organization_invitation"."response" in ('accepted', 'declined', 'revoked'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `organization_invitation_token_hash_unique` ON `organization_invitation` (`token_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `organization_invitation_open_unique` ON `organization_invitation` (`organization_id`,`email`) WHERE "organization_invitation"."response" is null;--> statement-breakpoint
CREATE INDEX `idx_organization_invitation_email` ON `organization_invitation` (`email`);