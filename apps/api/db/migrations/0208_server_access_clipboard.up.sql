ALTER TABLE server_access_servers ADD COLUMN IF NOT EXISTS clipboard_policy text NOT NULL DEFAULT 'off';
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='server_access_servers'::regclass AND conname='server_access_clipboard_policy') THEN
  ALTER TABLE server_access_servers ADD CONSTRAINT server_access_clipboard_policy CHECK (clipboard_policy IN ('off','paste','copy','both'));
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='server_access_servers'::regclass AND conname='server_access_clipboard_windows') THEN
  ALTER TABLE server_access_servers ADD CONSTRAINT server_access_clipboard_windows CHECK (os='windows' OR clipboard_policy='off');
 END IF;
END $$;
