CREATE TABLE IF NOT EXISTS devcollection_heads (
    stream text PRIMARY KEY,
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_event_digest bytea NOT NULL DEFAULT decode(repeat('00',32),'hex') CHECK (octet_length(last_event_digest)=32),
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO devcollection_heads(stream) VALUES ('collection.deposits') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS devcollection_outbox (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    receipt_key text UNIQUE, -- only the original add owns the idempotency key
    event_id uuid NOT NULL UNIQUE,
    stream text NOT NULL REFERENCES devcollection_heads(stream),
    event_type text NOT NULL CHECK (event_type='ReceiptConfirmed'),
    schema_version integer NOT NULL CHECK (schema_version=1),
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    payload bytea NOT NULL,
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest)=32),
    sequence bigint CHECK (sequence>0),
    prev_digest bytea CHECK (octet_length(prev_digest)=32),
    event_digest bytea CHECK (octet_length(event_digest)=32),
    key_id text,
    signature bytea,
    sequenced_at timestamptz,
    UNIQUE (stream,sequence),
    CHECK ((sequence IS NULL) = (signature IS NULL)
       AND (sequence IS NULL) = (key_id IS NULL)
       AND (sequence IS NULL) = (prev_digest IS NULL)
       AND (sequence IS NULL) = (event_digest IS NULL)
       AND (sequence IS NULL) = (sequenced_at IS NULL))
);

CREATE INDEX IF NOT EXISTS devcollection_pending ON devcollection_outbox(stream,id) WHERE sequence IS NULL;

-- An outbox row allows exactly the sequencer's unsigned -> sealed transition.
CREATE OR REPLACE FUNCTION devcollection_seal_once() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    seal_columns text[] := ARRAY['sequence','signature','key_id','prev_digest','event_digest','sequenced_at'];
BEGIN
    IF TG_OP <> 'UPDATE' OR OLD.sequence IS NOT NULL OR NEW.sequence IS NULL THEN
        RAISE EXCEPTION 'sealed development events are immutable';
    END IF;
    IF (to_jsonb(NEW) - seal_columns) IS DISTINCT FROM (to_jsonb(OLD) - seal_columns) THEN
        RAISE EXCEPTION 'development event content is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE TRIGGER devcollection_seal BEFORE UPDATE OR DELETE ON devcollection_outbox
    FOR EACH ROW EXECUTE FUNCTION devcollection_seal_once();
