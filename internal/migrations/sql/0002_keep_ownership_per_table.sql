-- keep_ownership() of 0001 named every table's columns in one expression, so
-- PL/pgSQL failed on the field the firing table lacks and refused every
-- legitimate update of definitions and secrets. Each table's check is now
-- evaluated only for that table.
CREATE OR REPLACE FUNCTION {{schema}}.keep_ownership() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'definitions' THEN
        IF (NEW.team_id, NEW.environment_id, NEW.scope, NEW.flow_id) IS DISTINCT FROM (OLD.team_id, OLD.environment_id, OLD.scope, OLD.flow_id) THEN
            RAISE EXCEPTION 'definition ownership and binding are immutable';
        END IF;
    ELSIF TG_TABLE_NAME = 'secrets' THEN
        IF (NEW.team_id, NEW.secret_id, NEW.environment_id, NEW.key) IS DISTINCT FROM (OLD.team_id, OLD.secret_id, OLD.environment_id, OLD.key) THEN
            RAISE EXCEPTION 'secret ownership and key are immutable';
        END IF;
    END IF;
    RETURN NEW;
END
$$;
