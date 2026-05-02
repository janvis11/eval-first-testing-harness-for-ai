-- Supabase Table Schema for piie
-- Run this in your Supabase project's SQL Editor to create the required tables

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenants table
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    metadata_json JSONB,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Policies table
CREATE TABLE IF NOT EXISTS policies (
    policy_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    entity_types TEXT NOT NULL,
    action VARCHAR(32) NOT NULL,
    description TEXT,
    version VARCHAR(32) DEFAULT '1.0.0',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_policies_active ON policies(active);

-- Audit events table
CREATE TABLE IF NOT EXISTS audit_events (
    event_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    trace_id VARCHAR(64) NOT NULL,
    action VARCHAR(32) NOT NULL,
    entities_found JSONB,
    risk_score DOUBLE PRECISION,
    policy_id VARCHAR(64) REFERENCES policies(policy_id),
    request_path VARCHAR(512),
    request_method VARCHAR(16),
    transformations TEXT,
    metadata_json JSONB,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_timestamp ON audit_events(tenant_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_trace ON audit_events(trace_id);

-- Token mappings table (for pseudonymization)
CREATE TABLE IF NOT EXISTS token_mappings (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    original_hash VARCHAR(64) NOT NULL,
    token VARCHAR(255) NOT NULL,
    entity_type VARCHAR(64) NOT NULL,
    namespace VARCHAR(64) DEFAULT 'default',
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tokens_tenant_original ON token_mappings(tenant_id, original_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_token ON token_mappings(token);

-- API keys table
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    scopes JSONB NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);

-- Row Level Security (RLS) Policies
-- Enable RLS on all tables
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE token_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- Tenants: Users can only access their own tenant data
CREATE POLICY "Users can view own tenant" ON tenants
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM api_keys
            WHERE api_keys.tenant_id = tenants.tenant_id
            AND api_keys.active = TRUE
        )
    );

-- Policies: Tenants can only access their own policies
CREATE POLICY "Tenants can view own policies" ON policies
    FOR SELECT
    USING (
        tenant_id = current_setting('app.current_tenant', TRUE)
        OR EXISTS (
            SELECT 1 FROM api_keys
            WHERE api_keys.tenant_id = policies.tenant_id
            AND api_keys.active = TRUE
        )
    );

CREATE POLICY "Tenants can insert own policies" ON policies
    FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM api_keys
            WHERE api_keys.tenant_id = policies.tenant_id
            AND api_keys.active = TRUE
        )
    );

CREATE POLICY "Tenants can update own policies" ON policies
    FOR UPDATE
    USING (
        EXISTS (
            SELECT 1 FROM api_keys
            WHERE api_keys.tenant_id = policies.tenant_id
            AND api_keys.active = TRUE
        )
    );

CREATE POLICY "Tenants can delete own policies" ON policies
    FOR DELETE
    USING (
        EXISTS (
            SELECT 1 FROM api_keys
            WHERE api_keys.tenant_id = policies.tenant_id
            AND api_keys.active = TRUE
        )
    );

-- Audit events: Tenants can only access their own audit events
CREATE POLICY "Tenants can view own audit events" ON audit_events
    FOR SELECT
    USING (
        tenant_id = current_setting('app.current_tenant', TRUE)
        OR EXISTS (
            SELECT 1 FROM api_keys
            WHERE api_keys.tenant_id = audit_events.tenant_id
            AND api_keys.active = TRUE
        )
    );

CREATE POLICY "Tenants can insert own audit events" ON audit_events
    FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM api_keys
            WHERE api_keys.tenant_id = audit_events.tenant_id
            AND api_keys.active = TRUE
        )
    );

CREATE POLICY "Tenants can delete own audit events" ON audit_events
    FOR DELETE
    USING (
        EXISTS (
            SELECT 1 FROM api_keys
            WHERE api_keys.tenant_id = audit_events.tenant_id
            AND api_keys.active = TRUE
        )
    );

-- Token mappings: Tenants can only access their own tokens
CREATE POLICY "Tenants can view own tokens" ON token_mappings
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM api_keys
            WHERE api_keys.tenant_id = token_mappings.tenant_id
            AND api_keys.active = TRUE
        )
    );

CREATE POLICY "Tenants can insert own tokens" ON token_mappings
    FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM api_keys
            WHERE api_keys.tenant_id = token_mappings.tenant_id
            AND api_keys.active = TRUE
        )
    );

CREATE POLICY "Tenants can delete own tokens" ON token_mappings
    FOR DELETE
    USING (
        EXISTS (
            SELECT 1 FROM api_keys
            WHERE api_keys.tenant_id = token_mappings.tenant_id
            AND api_keys.active = TRUE
        )
    );

-- API keys: Tenants can only access their own API keys
CREATE POLICY "Tenants can view own API keys" ON api_keys
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM api_keys ak
            WHERE ak.tenant_id = api_keys.tenant_id
            AND ak.active = TRUE
        )
    );

CREATE POLICY "Tenants can insert own API keys" ON api_keys
    FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM api_keys ak
            WHERE ak.tenant_id = api_keys.tenant_id
            AND ak.active = TRUE
        )
    );

CREATE POLICY "Tenants can update own API keys" ON api_keys
    FOR UPDATE
    USING (
        EXISTS (
            SELECT 1 FROM api_keys ak
            WHERE ak.tenant_id = api_keys.tenant_id
            AND ak.active = TRUE
        )
    );

CREATE POLICY "Tenants can delete own API keys" ON api_keys
    FOR DELETE
    USING (
        EXISTS (
            SELECT 1 FROM api_keys ak
            WHERE ak.tenant_id = api_keys.tenant_id
            AND ak.active = TRUE
        )
    );

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_policies_updated_at BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
