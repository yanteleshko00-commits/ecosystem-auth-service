CREATE TABLE IF NOT EXISTS support_items (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 kind text NOT NULL CHECK(kind IN ('message','reply','note','credits','project')),
 title text NOT NULL CHECK(char_length(title)<=180),
 body text NOT NULL DEFAULT '' CHECK(char_length(body)<=2000),
 project_job uuid, project_cap text, project_origin text,
 created_at timestamptz NOT NULL DEFAULT now(),
 read_at timestamptz
);
CREATE INDEX IF NOT EXISTS support_items_user_created ON support_items(user_id,created_at DESC);
