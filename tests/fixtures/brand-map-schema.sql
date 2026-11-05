-- Extracted verbatim from Brand Map migration; see brand-map-schema.json.
-- Requires PostgreSQL 18 (uuidv7). The file-service table below is a fixture stub.
CREATE TABLE file (id uuid PRIMARY KEY);

CREATE TYPE curator_status_enum AS ENUM (
  'pending',
  'approved',
  'active',
  'suspended',
  'demoted',
  'archived'
);

CREATE TYPE customer_status_enum AS ENUM (
  'active',
  'disabled',
  'banned',
  'deleted'
);

CREATE TYPE customer_type_enum AS ENUM (
  'guest',
  'registered'
);

CREATE TYPE organization_status_enum AS ENUM (
  'pending_review',
  'approved',
  'rejected',
  'suspended'
);

CREATE TABLE auth_account (
  id uuid DEFAULT uuidv7 () NOT NULL,
  account_id text NOT NULL,
  provider_id text NOT NULL,
  user_id uuid NOT NULL,
  access_token text,
  refresh_token text,
  id_token text,
  access_token_expires_at timestamp(6) with time zone,
  refresh_token_expires_at timestamp(6) with time zone,
  scope text,
  password text,
  created_at timestamp(6) with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
  updated_at timestamp(6) with time zone NOT NULL
);

CREATE TABLE auth_invitation (
  id uuid DEFAULT uuidv7 () NOT NULL,
  organization_id uuid NOT NULL,
  email text NOT NULL,
  role text,
  status text DEFAULT 'pending'::text NOT NULL,
  expires_at timestamp(6) with time zone NOT NULL,
  created_at timestamp(6) with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
  inviter_id uuid NOT NULL
);

CREATE TABLE auth_member (
  id uuid DEFAULT uuidv7 () NOT NULL,
  organization_id uuid NOT NULL,
  user_id uuid NOT NULL,
  role text DEFAULT 'member'::text NOT NULL,
  created_at timestamp(6) with time zone NOT NULL
);

CREATE TABLE auth_organization (
  id uuid DEFAULT uuidv7 () NOT NULL,
  name text NOT NULL,
  slug text NOT NULL,
  logo text,
  created_at timestamp(6) with time zone NOT NULL,
  metadata text,
  status organization_status_enum DEFAULT 'pending_review'::organization_status_enum NOT NULL,
  status_reason text,
  creator_id uuid,
  reviewed_at timestamp(6) with time zone,
  reviewed_by uuid,
  logo_file_id uuid,
  CONSTRAINT auth_organization_slug_format_ck CHECK (((length(slug) >= 1) AND (length(slug) <= 128) AND (slug ~
    '^[a-z0-9]+(-[a-z0-9]+)*$'::text))),
  CONSTRAINT auth_organization_slug_length_ck CHECK (((length(slug) >= 1) AND (length(slug) <= 128)))
);

CREATE TABLE auth_organization_role (
  id uuid DEFAULT uuidv7 () NOT NULL,
  organization_id uuid NOT NULL,
  role text NOT NULL,
  permission text NOT NULL,
  created_at timestamp(6) with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
  updated_at timestamp(6) with time zone
);

CREATE TABLE auth_session (
  id uuid DEFAULT uuidv7 () NOT NULL,
  expires_at timestamp(6) with time zone NOT NULL,
  token text NOT NULL,
  created_at timestamp(6) with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
  updated_at timestamp(6) with time zone NOT NULL,
  ip_address text,
  user_agent text,
  user_id uuid NOT NULL,
  "activeOrganizationId" text,
  impersonated_by text
);

CREATE TABLE auth_two_factor (
  id uuid DEFAULT uuidv7 () NOT NULL,
  secret text NOT NULL,
  backup_codes text NOT NULL,
  user_id uuid NOT NULL,
  verified boolean DEFAULT TRUE,
  failed_verification_count integer DEFAULT 0,
  locked_until timestamp(6) with time zone
);

CREATE TABLE auth_user (
  id uuid DEFAULT uuidv7 () NOT NULL,
  name text NOT NULL,
  first_name text,
  last_name text,
  birth_date timestamp(6) with time zone,
  email text NOT NULL,
  email_verified boolean DEFAULT FALSE NOT NULL,
  image text,
  image_miniature text,
  created_at timestamp(6) with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
  updated_at timestamp(6) with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
  deleted_at timestamp(6) with time zone,
  is_anonymous boolean DEFAULT FALSE,
  phone_number text,
  phone_number_verified boolean,
  two_factor_enabled boolean DEFAULT FALSE,
  username text,
  display_username text,
  role text,
  banned boolean DEFAULT FALSE,
  ban_reason text,
  ban_expires timestamp(6) with time zone,
  metadata jsonb,
  patronymic text,
  bio text,
  gender text,
  city text,
  cover text,
  social_links jsonb DEFAULT '[]'::jsonb,
  customer_type customer_type_enum DEFAULT 'registered'::customer_type_enum NOT NULL,
  customer_status customer_status_enum DEFAULT 'active'::customer_status_enum NOT NULL,
  last_login_at timestamp with time zone,
  curator_application jsonb,
  curator_status curator_status_enum,
  curator_status_reason text,
  curator_status_changed_at timestamp with time zone,
  curator_status_changed_by uuid,
  curator_subscribers_count bigint DEFAULT 0 NOT NULL,
  curator_likes_count bigint DEFAULT 0 NOT NULL,
  curator_finds_count bigint DEFAULT 0 NOT NULL,
  curator_collections_count bigint DEFAULT 0 NOT NULL,
  curator_subscriptions_count bigint DEFAULT 0 NOT NULL,
  curator_rank integer DEFAULT 0 NOT NULL,
  image_file_id uuid,
  image_miniature_file_id uuid,
  cover_file_id uuid,
  CONSTRAINT auth_user_display_username_format_ck CHECK (((display_username IS NULL) OR (display_username ~ '^[A-Za-z0-9_.]{4,64}$'::text))),
  CONSTRAINT auth_user_username_format_ck CHECK (((username IS NULL) OR (username ~ '^[A-Za-z0-9_.]{4,64}$'::text)))
);

CREATE TABLE auth_verification (
  id uuid DEFAULT uuidv7 () NOT NULL,
  identifier text NOT NULL,
  value text NOT NULL,
  expires_at timestamp(6) with time zone NOT NULL,
  created_at timestamp(6) with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
  updated_at timestamp(6) with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE jwks (
  id uuid DEFAULT uuidv7 () NOT NULL,
  public_key text NOT NULL,
  private_key text NOT NULL,
  created_at timestamp(6) with time zone NOT NULL,
  expires_at timestamp(6) with time zone,
  alg text,
  crv text
);

ALTER TABLE ONLY auth_account
  ADD CONSTRAINT auth_account_pkey PRIMARY KEY (id);

ALTER TABLE ONLY auth_invitation
  ADD CONSTRAINT auth_invitation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY auth_member
  ADD CONSTRAINT auth_member_pkey PRIMARY KEY (id);

ALTER TABLE ONLY auth_organization
  ADD CONSTRAINT auth_organization_pkey PRIMARY KEY (id);

ALTER TABLE ONLY auth_organization_role
  ADD CONSTRAINT auth_organization_role_pkey PRIMARY KEY (id);

ALTER TABLE ONLY auth_session
  ADD CONSTRAINT auth_session_pkey PRIMARY KEY (id);

ALTER TABLE ONLY auth_two_factor
  ADD CONSTRAINT auth_two_factor_pkey PRIMARY KEY (id);

ALTER TABLE ONLY auth_user
  ADD CONSTRAINT auth_user_pkey PRIMARY KEY (id);

ALTER TABLE ONLY auth_verification
  ADD CONSTRAINT auth_verification_pkey PRIMARY KEY (id);

ALTER TABLE ONLY jwks
  ADD CONSTRAINT jwks_pkey PRIMARY KEY (id);

CREATE INDEX auth_account_user_id_idx ON auth_account USING btree (user_id);

CREATE INDEX auth_invitation_email_idx ON auth_invitation USING btree (email);

CREATE INDEX auth_invitation_organization_id_idx ON auth_invitation USING btree (organization_id);

CREATE INDEX auth_member_organization_id_idx ON auth_member USING btree (organization_id);

CREATE INDEX auth_member_user_id_idx ON auth_member USING btree (user_id);

CREATE INDEX auth_organization_creator_id_idx ON auth_organization USING btree (creator_id);

CREATE INDEX auth_organization_logo_file_id_idx ON auth_organization USING btree (logo_file_id);

CREATE INDEX auth_organization_role_organization_id_idx ON auth_organization_role USING btree (organization_id);

CREATE UNIQUE INDEX auth_organization_role_organization_role_uidx ON auth_organization_role USING btree
  (organization_id, ROLE);

CREATE INDEX auth_organization_role_role_idx ON auth_organization_role USING btree (ROLE);

CREATE UNIQUE INDEX auth_organization_slug_key ON auth_organization USING btree (slug);

CREATE UNIQUE INDEX auth_organization_slug_uidx ON auth_organization USING btree (slug);

CREATE INDEX auth_organization_status_idx ON auth_organization USING btree (status);

CREATE UNIQUE INDEX auth_session_token_key ON auth_session USING btree (token);

CREATE INDEX auth_session_user_id_idx ON auth_session USING btree (user_id);

CREATE INDEX auth_two_factor_secret_idx ON auth_two_factor USING btree (secret);

CREATE INDEX auth_two_factor_user_id_idx ON auth_two_factor USING btree (user_id);

CREATE INDEX auth_user_cover_file_id_idx ON auth_user USING btree (cover_file_id);

CREATE INDEX auth_user_curator_collections_count_idx ON auth_user USING btree (curator_collections_count, id);

CREATE INDEX auth_user_curator_finds_count_idx ON auth_user USING btree (curator_finds_count, id);

CREATE INDEX auth_user_curator_likes_count_idx ON auth_user USING btree (curator_likes_count, id);

CREATE INDEX auth_user_curator_rank_idx ON auth_user USING btree (curator_rank, id);

CREATE INDEX auth_user_curator_status_idx ON auth_user USING btree (curator_status);

CREATE INDEX auth_user_curator_subscribers_count_idx ON auth_user USING btree (curator_subscribers_count, id);

CREATE INDEX auth_user_curator_subscriptions_count_idx ON auth_user USING btree (curator_subscriptions_count, id);

CREATE INDEX auth_user_customer_status_idx ON auth_user USING btree (customer_status);

CREATE INDEX auth_user_customer_type_idx ON auth_user USING btree (customer_type);

CREATE INDEX auth_user_deleted_at_idx ON auth_user USING btree (deleted_at);

CREATE UNIQUE INDEX auth_user_email_key ON auth_user USING btree (email);

CREATE INDEX auth_user_image_file_id_idx ON auth_user USING btree (image_file_id);

CREATE INDEX auth_user_image_miniature_file_id_idx ON auth_user USING btree (image_miniature_file_id);

CREATE UNIQUE INDEX auth_user_phone_number_key ON auth_user USING btree (phone_number);

CREATE UNIQUE INDEX auth_user_username_key ON auth_user USING btree (username);

CREATE INDEX auth_verification_identifier_idx ON auth_verification USING btree (identifier);

ALTER TABLE ONLY auth_account
  ADD CONSTRAINT auth_account_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth_user (id) ON DELETE CASCADE;

ALTER TABLE ONLY auth_invitation
  ADD CONSTRAINT auth_invitation_inviter_id_fkey FOREIGN KEY (inviter_id) REFERENCES auth_user (id) ON DELETE CASCADE;

ALTER TABLE ONLY auth_invitation
  ADD CONSTRAINT auth_invitation_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES
    auth_organization (id) ON DELETE CASCADE;

ALTER TABLE ONLY auth_member
  ADD CONSTRAINT auth_member_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES auth_organization
    (id) ON DELETE CASCADE;

ALTER TABLE ONLY auth_member
  ADD CONSTRAINT auth_member_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth_user (id) ON DELETE CASCADE;

ALTER TABLE ONLY auth_organization
  ADD CONSTRAINT auth_organization_creator_id_fkey FOREIGN KEY (creator_id) REFERENCES auth_user (id) ON UPDATE CASCADE;

ALTER TABLE ONLY auth_organization
  ADD CONSTRAINT auth_organization_logo_file_id_fk FOREIGN KEY (logo_file_id) REFERENCES file (id) ON DELETE SET NULL;

ALTER TABLE ONLY auth_organization
  ADD CONSTRAINT auth_organization_reviewed_by_fkey FOREIGN KEY (reviewed_by) REFERENCES auth_user (id) ON
    UPDATE CASCADE ON DELETE SET NULL;

ALTER TABLE ONLY auth_organization_role
  ADD CONSTRAINT auth_organization_role_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES
    auth_organization (id) ON DELETE CASCADE;

ALTER TABLE ONLY auth_session
  ADD CONSTRAINT auth_session_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth_user (id) ON DELETE CASCADE;

ALTER TABLE ONLY auth_two_factor
  ADD CONSTRAINT auth_two_factor_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth_user (id) ON DELETE CASCADE;

ALTER TABLE ONLY auth_user
  ADD CONSTRAINT auth_user_cover_file_id_fk FOREIGN KEY (cover_file_id) REFERENCES file (id) ON DELETE SET NULL;

ALTER TABLE ONLY auth_user
  ADD CONSTRAINT auth_user_image_file_id_fk FOREIGN KEY (image_file_id) REFERENCES file (id) ON DELETE SET NULL;

ALTER TABLE ONLY auth_user
  ADD CONSTRAINT auth_user_image_miniature_file_id_fk FOREIGN KEY (image_miniature_file_id) REFERENCES file
    (id) ON DELETE SET NULL;
