
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

create table if not exists data_logger
(
    url_scheme           text    default ''::text     not null,
    url_host             text                         not null,
    url_path             text    default ''::text     not null,
    date_found           timestamp with time zone     not null,
    req_method           text    default ''::text     not null,
    param_keys           text[]  default '{}'::text[] not null,
    header_keys_req      text[]  default '{}'::text[] not null,
    header_keys_resp     text[]  default '{}'::text[] not null,
    cookie_keys          text[]  default '{}'::text[] not null,
    resp_code            integer default 0            not null,
    param_key_vals       text[]  default '{}'::text[] not null,
    header_key_vals_req  text[]  default '{}'::text[] not null,
    header_key_vals_resp text[]  default '{}'::text[] not null,
    cookie_key_vals      text[]  default '{}'::text[] not null,
    last_seen            timestamp with time zone     not null,
    constraint data_logger_pk
        primary key (url_scheme, url_host, url_path, req_method, resp_code)
);

comment on table data_logger is 'Identify web assets using a unique combination of URL scheme, URL host, URL path, HTTP request method, and HTTP response code.';

comment on column data_logger.url_scheme is 'Scheme portion of the URL (e.g. "http", "https", "file", "ssh"; case-insensitive, normalized to lowercase)';

comment on column data_logger.url_host is 'Host portion of the URL (e.g. "example.com"). Case-insensitive, normalized to lowercase.';

comment on column data_logger.url_path is 'Path portion of a URL (e.g. "/admin", "/get/config"). Case-sensitive.';

comment on column data_logger.date_found is 'Timestamp when this asset was first discovered.';

comment on column data_logger.req_method is 'HTTP request method (e.g. "GET", "POST", "PUT", etc.). Case-sensitive.';

comment on column data_logger.param_keys is 'Parameter portion of URL (e.g. "a=b", "id=1234"). Case-sensitive. Keys only.';

comment on column data_logger.header_keys_req is 'HTTP request headers (e.g. "Host", "Accept"). Case-insensitive. Keys only.';

comment on column data_logger.header_keys_resp is 'HTTP response headers (e.g. "Content-Type", "Server"). Case-insensitive. Keys only.';

comment on column data_logger.cookie_keys is 'Cookies sent in either HTTP requests or responses (e.g. "language", "cart"). Case-insensitive. Keys only.';

comment on column data_logger.resp_code is 'HTTP response code (e.g. 200, 300, 403).';

comment on column data_logger.param_key_vals is 'Parameter portion of URL (e.g. "a=b", "id=1234"). Case-sensitive. Key-value pairs.';

comment on column data_logger.header_key_vals_req is 'HTTP request headers (e.g. "Host: www.example.com", "Accept: text/html"). Case-insensitive. Key-value pairs.';

comment on column data_logger.header_key_vals_resp is 'HTTP response headers (e.g. "Content-Type: text/html; charset=utf-8", "Server: Apache/2.4.46 (Ubuntu)"). Case-insensitive. Key-value pairs.';

comment on column data_logger.cookie_key_vals is 'Cookies sent in either HTTP requests or responses (e.g. "language: en", "cart:item1=1&item2=2"). Case-insensitive. Key-value pairs.';

comment on column data_logger.last_seen is 'Timestamp when this asset was last observed.';

create table if not exists config_logger
(
    enabled boolean default true             not null,
    targets uuid[]  default ARRAY []::uuid[] not null,
    ignored uuid[]  default ARRAY []::uuid[] not null
);

create table if not exists data_api_hunter
(
    url_scheme      text                     not null,
    url_host        text                     not null,
    url_path        text                     not null,
    req_method      text                     not null,
    req_body_json   jsonb,
    req_body_plain  text,
    resp_body_json  jsonb,
    resp_body_plain text,
    resp_code       integer default 0        not null,
    timestamp       timestamp with time zone not null
);

comment on table data_api_hunter is 'API data observed in HTTP requests and responses.';

create index if not exists data_api_hunter_index
    on data_api_hunter (url_scheme, url_host, url_path, req_method, resp_code);

create table if not exists data_injector
(
);

create table if not exists config_blocker
(
);

create table if not exists data_blocker
(
);

create table if not exists config_analyzer
(
);

create table if not exists data_analyzer
(
);

create table if not exists config_crawler
(
);

create table if not exists data_crawler
(
);

create table if not exists config_dns
(
);

create table if not exists data_dns
(
);

create table if not exists config_injector
(
    enabled     boolean default true not null,
    targets     uuid[]  default ARRAY []::uuid[],
    ignored     uuid[]  default ARRAY []::uuid[],
    script_urls uuid[]  default ARRAY []::uuid[]
);

comment on column config_injector.targets is 'An array of UUID values referencing the IDs in the "targets" table.';

comment on column config_injector.ignored is 'An array of UUID values referencing the IDs in the "targets" table.';

comment on column config_injector.script_urls is 'An array of UUID values referencing the IDs in the "injector_script_urls" table.';

create table if not exists injector_script_urls
(
    id  uuid not null,
    url text not null,
    constraint injector_script_urls_pk
        primary key (id)
);

create unique index if not exists injector_script_urls_id_uindex
    on injector_script_urls (id);

create table if not exists targets
(
    id     uuid    not null,
    ignore boolean not null,
    target jsonb   not null,
    constraint targets_pk
        primary key (id)
);

comment on table targets is 'targets stored in proxy filter format';

comment on column targets.target is 'Stored in proxy filter format.';

create unique index if not exists targets_id_uindex
    on targets (id);

create table if not exists data_mapper
(
    referer_scheme     text default ''::text    not null,
    referer_host       text default ''::text    not null,
    referer_path       text default ''::text    not null,
    destination_scheme text                     not null,
    destination_host   text                     not null,
    destination_path   text                     not null,
    first_seen         timestamp with time zone not null,
    last_seen          timestamp with time zone not null,
    constraint data_mapper_pk
        primary key (referer_scheme, referer_host, referer_path, destination_scheme, destination_host, destination_path)
);

comment on table data_mapper is 'Data for the mapper plugin';

comment on column data_mapper.referer_scheme is 'URL scheme in the referer header. Contains empty text if no referer header present (i.e. direct browse).';

comment on column data_mapper.referer_host is 'URL host in the referer header. Contains empty text if no referer header present (i.e. direct browse).';

comment on column data_mapper.referer_path is 'URL path in the referer header. Contains empty text if no referer header present (i.e. direct browse).';

comment on column data_mapper.destination_scheme is 'URL scheme for the destination.';

comment on column data_mapper.destination_host is 'URL host for the destination.';

comment on column data_mapper.destination_path is 'URL path for the destination.';

comment on column data_mapper.first_seen is 'Time when this data was first seen.';

comment on column data_mapper.last_seen is 'Time when this data was most recently seen.';

comment on constraint data_mapper_pk on data_mapper is 'Primary, unique key for mapper plugin data.';

create table if not exists config_mapper
(
    enabled boolean default true             not null,
    targets uuid[]  default ARRAY []::uuid[] not null,
    ignored uuid[]  default ARRAY []::uuid[] not null
);

create table if not exists corpus_url_path_parts
(
    name     varchar(50)                                         not null,
    count    integer                  default 1                  not null,
    keep     boolean                  default true               not null,
    flagged  boolean                  default false              not null,
    reviewed boolean                  default false              not null,
    found    timestamp with time zone default CURRENT_TIMESTAMP  not null,
    id       uuid                     default uuid_generate_v4() not null,
    primary key (id),
    unique (name)
);

create index if not exists idx_corpus_url_path_parts_flagged
    on corpus_url_path_parts (flagged);

create index if not exists idx_corpus_url_path_parts_reviewed
    on corpus_url_path_parts (reviewed);

create index if not exists idx_corpus_url_path_parts_found
    on corpus_url_path_parts (found);

create table if not exists corpus_http_header_keys
(
    name     varchar(50)                                         not null,
    count    integer                  default 1                  not null,
    keep     boolean                  default true               not null,
    flagged  boolean                  default false              not null,
    reviewed boolean                  default false              not null,
    found    timestamp with time zone default CURRENT_TIMESTAMP  not null,
    id       uuid                     default uuid_generate_v4() not null,
    primary key (id),
    unique (name)
);

create index if not exists idx_corpus_http_header_keys_flagged
    on corpus_http_header_keys (flagged);

create index if not exists idx_corpus_http_header_keys_reviewed
    on corpus_http_header_keys (reviewed);

create index if not exists idx_corpus_http_header_keys_found
    on corpus_http_header_keys (found);

create table if not exists corpus_url_param_keys
(
    name     varchar(100)                                        not null,
    count    integer                  default 1                  not null,
    keep     boolean                  default true               not null,
    flagged  boolean                  default false              not null,
    reviewed boolean                  default false              not null,
    found    timestamp with time zone default CURRENT_TIMESTAMP  not null,
    id       uuid                     default uuid_generate_v4() not null,
    primary key (id),
    unique (name)
);

create index if not exists idx_corpus_url_param_keys_flagged
    on corpus_url_param_keys (flagged);

create index if not exists idx_corpus_url_param_keys_reviewed
    on corpus_url_param_keys (reviewed);

create index if not exists idx_corpus_url_param_keys_found
    on corpus_url_param_keys (found);

create table if not exists corpus_server_header_values
(
    name     varchar(100)                                        not null,
    count    integer                  default 1                  not null,
    keep     boolean                  default true               not null,
    flagged  boolean                  default false              not null,
    reviewed boolean                  default false              not null,
    found    timestamp with time zone default CURRENT_TIMESTAMP  not null,
    id       uuid                     default uuid_generate_v4() not null,
    primary key (id),
    unique (name)
);

create index if not exists idx_corpus_server_header_values_flagged
    on corpus_server_header_values (flagged);

create index if not exists idx_corpus_server_header_values_reviewed
    on corpus_server_header_values (reviewed);

create index if not exists idx_corpus_server_header_values_found
    on corpus_server_header_values (found);

create table if not exists corpus_file_extensions
(
    name     varchar(50)                                         not null,
    count    integer                  default 1                  not null,
    keep     boolean                  default true               not null,
    flagged  boolean                  default false              not null,
    reviewed boolean                  default false              not null,
    found    timestamp with time zone default CURRENT_TIMESTAMP  not null,
    id       uuid                     default uuid_generate_v4() not null,
    primary key (id),
    unique (name)
);

create index if not exists idx_corpus_file_extensions_flagged
    on corpus_file_extensions (flagged);

create index if not exists idx_corpus_file_extensions_reviewed
    on corpus_file_extensions (reviewed);

create index if not exists idx_corpus_file_extensions_found
    on corpus_file_extensions (found);

create table if not exists users
(
    username   text                                   not null,
    password   text                                   not null,
    email      text,
    created_at timestamp with time zone default now() not null,
    roles      integer[],
    constraint users_pk
        primary key (username)
);

comment on column users.password is 'Password is stored as an Argon2id hash.';

comment on column users.roles is 'User roles, using the IDs from the user_roles table.';

create table if not exists corpus_cookie_keys
(
    name     varchar(100)                                        not null,
    count    integer                  default 1                  not null,
    keep     boolean                  default true               not null,
    flagged  boolean                  default false              not null,
    reviewed boolean                  default false              not null,
    found    timestamp with time zone default CURRENT_TIMESTAMP  not null,
    id       uuid                     default uuid_generate_v4() not null,
    primary key (id),
    unique (name)
);

create index if not exists idx_corpus_cookie_keys_flagged
    on corpus_cookie_keys (flagged);

create index if not exists idx_corpus_cookie_keys_reviewed
    on corpus_cookie_keys (reviewed);

create index if not exists idx_corpus_cookie_keys_found
    on corpus_cookie_keys (found);

create table if not exists vectors
(
    url_scheme     text    not null,
    url_host       text    not null,
    url_path       text    not null,
    vector         real[]  not null,
    vector_version integer not null,
    constraint vectors_pk
        primary key (url_scheme, url_host, url_path)
);

create table if not exists classifications
(
    url_scheme text    not null,
    url_host   text    not null,
    url_path   text    not null,
    class      integer not null,
    constraint classifications_pk
        primary key (url_scheme, url_host, url_path)
);

create table if not exists user_roles
(
    id          integer not null,
    name        text    not null,
    description text    not null,
    constraint user_roles_pk
        primary key (id)
);

comment on table user_roles is 'User role descriptions';

comment on column user_roles.id is 'Role ID';

comment on column user_roles.name is 'Name of role';

comment on column user_roles.description is 'Description of role';

create or replace function get_subdomains()
    returns TABLE
            (
                domain    text,
                subdomain text
            )
    language plpgsql
as
$$
DECLARE
    recdomains     RECORD;
    recsubdomains  RECORD;
    regexsubdomain TEXT;
BEGIN
    -- Get all unique second-level domains (i.e. example.com or localhost)
    FOR recdomains IN (SELECT DISTINCT unnest(regexp_matches(url_host,
                                                             '([a-zA-Z0-9\-_]+|[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)$')) AS domain
                       FROM data_logger)
        LOOP
            -- Search for all subdomains for each second-level domain
            regexsubdomain := '(^([a-zA-Z0-9\-_\.]+\.' || recdomains.domain || ')$)';
            FOR recsubdomains IN (SELECT DISTINCT unnest(regexp_matches(url_host, regexsubdomain)) AS subdomain
                                  FROM data_logger)
                LOOP
                    -- Assign the domain and subdomain to the table we're returning
                    domain := recdomains.domain;
                    subdomain := recsubdomains.subdomain;
                    RETURN NEXT;
                END LOOP;
            RETURN NEXT;
            IF (SELECT COUNT(*)
                FROM (SELECT DISTINCT unnest(regexp_matches(url_host, regexsubdomain)) AS subdomain
                      FROM data_logger) AS matched) = 0 THEN
                domain := recdomains.domain;
                subdomain := '';
                RETURN NEXT;
            END IF;
        END LOOP;
END;
$$;

create or replace function inventory_data_exists(start_time timestamp with time zone, domains_regex text[],
                                                 paths_regex text[], resp_codes integer[], url_schemes_regex text[],
                                                 req_methods_regex text[], param_keys_regex text[],
                                                 param_key_values_regex text[], header_keys_req_regex text[],
                                                 header_key_values_req_regex text[], header_keys_resp_regex text[],
                                                 header_key_values_resp_regex text[], cookie_keys_regex text[],
                                                 cookie_key_values_regex text[]) returns boolean
    language plpgsql
as
$$
DECLARE
    rec_domain RECORD;
BEGIN
    -- Loop through all the given domains
    FOR rec_domain IN (SELECT DISTINCT url_host AS local_domain
                       FROM data_logger
                       WHERE url_host ~* ANY (domains_regex)
                       ORDER BY local_domain)
        LOOP
            -- Return true if there is any data matching the filters provided
            IF EXISTS(SELECT url_path AS local_path
                      FROM data_logger
                      WHERE url_host = rec_domain.local_domain
                        AND url_path ~ ANY (paths_regex)
                        AND date_found > start_time
                        AND resp_code = ANY (resp_codes)
                        AND url_scheme ~* ANY (url_schemes_regex)
                        AND req_method ~ ANY (req_methods_regex)
                        AND param_keys ~@ ANY (param_keys_regex)
                        AND param_key_vals ~@ ANY (param_key_values_regex)
                        AND header_keys_req ~*@ ANY (header_keys_req_regex)
                        AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
                        AND header_keys_resp ~*@ ANY (header_keys_resp_regex)
                        AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
                        AND cookie_keys ~*@ ANY (cookie_keys_regex)
                        AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) THEN
                RETURN TRUE;
            END IF;
        END LOOP;
    RETURN FALSE;
END;
$$;

create or replace function regexp_match_array(a text[], regexp text) returns boolean
    immutable
    strict
    language sql
as
$$
SELECT exists(SELECT * FROM unnest(a) AS x WHERE x ~* regexp);
$$;

comment on function regexp_match_array(text[], text) is 'returns TRUE if any element of a matches regexp';

create or replace function regexp_match_array_case_insensitive(a text[], regexp text) returns boolean
    immutable
    strict
    language sql
as
$$
SELECT exists(SELECT * FROM unnest(a) AS x WHERE x ~* regexp);
$$;

comment on function regexp_match_array_case_insensitive(text[], text) is 'returns TRUE if any element of a matches regexp';

create or replace function regexp_match_array_case_sensitive(a text[], regexp text) returns boolean
    immutable
    strict
    language sql
as
$$
SELECT exists(SELECT * FROM unnest(a) AS x WHERE x ~ regexp);
$$;

create or replace function regexp_not_match_array_case_insensitive(a text[], regexp text) returns boolean
    immutable
    strict
    language sql
as
$$
SELECT (exists(SELECT * FROM unnest(a) AS x WHERE x ~* regexp) is false);
$$;

create or replace function regexp_not_match_array_case_sensitive(a text[], regexp text) returns boolean
    immutable
    strict
    language sql
as
$$
SELECT (exists(SELECT * FROM unnest(a) AS x WHERE x ~ regexp) is false);
$$;

create or replace function get_inventory_data(start_time timestamp with time zone, end_time timestamp with time zone,
                                              domains_regex text[], paths_regex text[], resp_codes_int integer[],
                                              url_schemes_regex text[], req_methods_regex text[],
                                              param_key_values_regex text[], header_key_values_req_regex text[],
                                              header_key_values_resp_regex text[], cookie_key_values_regex text[])
    returns TABLE
            (
                host                    text,
                path_val                text,
                param_key_values        text[],
                headers_key_values_req  text[],
                headers_key_values_resp text[],
                cookies_key_values      text[],
                schemes                 text[],
                req_methods             text[],
                resp_codes              integer[],
                last_seen               timestamp with time zone
            )
    language plpgsql
as
$$
DECLARE
    rec_domain RECORD;
    rec_path   RECORD;
BEGIN
    -- Loop through all the given domains
    FOR rec_domain IN (SELECT DISTINCT url_host AS local_domain
                       FROM data_logger
                       WHERE url_host ~* ANY (domains_regex)
                         AND date_found >= start_time
                         AND last_seen <= end_time
                       ORDER BY local_domain)
        LOOP
            -- Loop through all unique paths for the domain
            FOR rec_path IN (SELECT DISTINCT url_path AS local_path
                             FROM data_logger
                             WHERE url_host = rec_domain.local_domain
                               AND url_path ~ ANY (paths_regex)
                               AND resp_code = ANY (resp_codes_int)
                               AND url_scheme ~* ANY (url_schemes_regex)
                               AND req_method ~ ANY (req_methods_regex)
                               AND param_key_vals ~@ ANY (param_key_values_regex)
                               AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
                               AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
                               AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)
                               AND date_found >= start_time
                               AND last_seen <= end_time
                             ORDER BY local_path)
                LOOP
                    -- Get the unique inventory values for the given path and domain
                    host := rec_domain.local_domain;
                    path_val := rec_path.local_path;
                    param_key_values := coalesce((SELECT array_agg(DISTINCT subq.val)
                                                  FROM (SELECT unnest(param_key_vals) AS val
                                                        FROM data_logger
                                                        WHERE url_host = rec_domain.local_domain
                                                          AND url_path = rec_path.local_path
                                                          AND date_found >= start_time
                                                          AND last_seen <= end_time
                                                          AND resp_code = ANY (resp_codes_int)
                                                          AND url_scheme ~* ANY (url_schemes_regex)
                                                          AND req_method ~ ANY (req_methods_regex)
                                                          AND param_key_vals ~@ ANY (param_key_values_regex)
                                                          AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
                                                          AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
                                                          AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq),
                                                 '{}');
                    headers_key_values_req := coalesce((SELECT array_agg(DISTINCT subq.val)
                                                        FROM (SELECT unnest(header_key_vals_req) AS val
                                                              FROM data_logger
                                                              WHERE url_host = rec_domain.local_domain
                                                                AND url_path = rec_path.local_path
                                                                AND date_found >= start_time
                                                                AND last_seen <= end_time
                                                                AND resp_code = ANY (resp_codes_int)
                                                                AND url_scheme ~* ANY (url_schemes_regex)
                                                                AND req_method ~ ANY (req_methods_regex)
                                                                AND param_key_vals ~@ ANY (param_key_values_regex)
                                                                AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
                                                                AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
                                                                AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq),
                                                       '{}');
                    headers_key_values_resp := coalesce((SELECT array_agg(DISTINCT subq.val)
                                                         FROM (SELECT unnest(header_key_vals_resp) AS val
                                                               FROM data_logger
                                                               WHERE url_host = rec_domain.local_domain
                                                                 AND url_path = rec_path.local_path
                                                                 AND date_found >= start_time
                                                                 AND last_seen <= end_time
                                                                 AND resp_code = ANY (resp_codes_int)
                                                                 AND url_scheme ~* ANY (url_schemes_regex)
                                                                 AND req_method ~ ANY (req_methods_regex)
                                                                 AND param_key_vals ~@ ANY (param_key_values_regex)
                                                                 AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
                                                                 AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
                                                                 AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq),
                                                        '{}');
                    cookies_key_values := coalesce((SELECT array_agg(DISTINCT subq.val)
                                                    FROM (SELECT unnest(cookie_key_vals) AS val
                                                          FROM data_logger
                                                          WHERE url_host = rec_domain.local_domain
                                                            AND url_path = rec_path.local_path
                                                            AND date_found >= start_time
                                                            AND last_seen <= end_time
                                                            AND resp_code = ANY (resp_codes_int)
                                                            AND url_scheme ~* ANY (url_schemes_regex)
                                                            AND req_method ~ ANY (req_methods_regex)
                                                            AND param_key_vals ~@ ANY (param_key_values_regex)
                                                            AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
                                                            AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
                                                            AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq),
                                                   '{}');
                    schemes := coalesce((SELECT array_agg(DISTINCT subq.val)
                                         FROM (SELECT url_scheme AS val
                                               FROM data_logger
                                               WHERE url_host = rec_domain.local_domain
                                                 AND url_path = rec_path.local_path
                                                 AND date_found >= start_time
                                                 AND last_seen <= end_time
                                                 AND resp_code = ANY (resp_codes_int)
                                                 AND url_scheme ~* ANY (url_schemes_regex)
                                                 AND req_method ~ ANY (req_methods_regex)
                                                 AND param_key_vals ~@ ANY (param_key_values_regex)
                                                 AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
                                                 AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
                                                 AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq), '{}');
                    req_methods := coalesce((SELECT array_agg(DISTINCT subq.val)
                                             FROM (SELECT req_method AS val
                                                   FROM data_logger
                                                   WHERE url_host = rec_domain.local_domain
                                                     AND url_path = rec_path.local_path
                                                     AND date_found >= start_time
                                                     AND last_seen <= end_time
                                                     AND resp_code = ANY (resp_codes_int)
                                                     AND url_scheme ~* ANY (url_schemes_regex)
                                                     AND req_method ~ ANY (req_methods_regex)
                                                     AND param_key_vals ~@ ANY (param_key_values_regex)
                                                     AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
                                                     AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
                                                     AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq),
                                            '{}');
                    resp_codes := coalesce((SELECT array_agg(DISTINCT subq.val)
                                            FROM (SELECT resp_code AS val
                                                  FROM data_logger
                                                  WHERE url_host = rec_domain.local_domain
                                                    AND url_path = rec_path.local_path
                                                    AND date_found >= start_time
                                                    AND last_seen <= end_time
                                                    AND resp_code = ANY (resp_codes_int)
                                                    AND url_scheme ~* ANY (url_schemes_regex)
                                                    AND req_method ~ ANY (req_methods_regex)
                                                    AND param_key_vals ~@ ANY (param_key_values_regex)
                                                    AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
                                                    AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
                                                    AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)) AS subq),
                                           '{}');
                    last_seen := (SELECT subq.val
                                  FROM (SELECT date_found AS val
                                        FROM data_logger
                                        WHERE url_host = rec_domain.local_domain
                                          AND url_path = rec_path.local_path
                                          AND date_found >= start_time
                                          AND last_seen <= end_time
                                          AND resp_code = ANY (resp_codes_int)
                                          AND url_scheme ~* ANY (url_schemes_regex)
                                          AND req_method ~ ANY (req_methods_regex)
                                          AND param_key_vals ~@ ANY (param_key_values_regex)
                                          AND header_key_vals_req ~*@ ANY (header_key_values_req_regex)
                                          AND header_key_vals_resp ~*@ ANY (header_key_values_resp_regex)
                                          AND cookie_key_vals ~*@ ANY (cookie_key_values_regex)
                                        ORDER BY date_found DESC
                                        LIMIT 1) AS subq);
                    RETURN NEXT;
                END LOOP;
        END LOOP;
END;
$$;

create or replace function notify_change_on_injector_script_urls() returns trigger
    language plpgsql
as
$$
DECLARE
    operation TEXT;
BEGIN
    IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        operation := 'UPDATE';
    ELSIF TG_OP = 'DELETE' THEN
        operation := 'DELETE';
    END IF;

    PERFORM pg_notify('injector_script_urls_channel', operation || ',' || NEW.id::text || ':' || NEW.url);
    RETURN NEW;
END;
$$;

create trigger injector_script_urls_trigger
    after insert or update or delete
    on injector_script_urls
    for each row
execute procedure notify_change_on_injector_script_urls();

create or replace function notify_change_on_targets() returns trigger
    language plpgsql
as
$$
DECLARE
    operation TEXT;
BEGIN
    IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        operation := 'UPDATE';
    ELSIF TG_OP = 'DELETE' THEN
        operation := 'DELETE';
    END IF;

    PERFORM pg_notify('targets_channel', operation || ',' || NEW.id::text || ':' || NEW.target::jsonb::text);
    RETURN NEW;
END;
$$;

create trigger targets_trigger
    after insert or update or delete
    on targets
    for each row
execute procedure notify_change_on_targets();

create or replace function get_hosts_within_three_degrees(p_host text)
    returns TABLE
            (
                host text
            )
    language sql
as
$$
WITH RECURSIVE cte(host, depth) AS (
    -- Base case: 1st degree hosts
    SELECT destination_host, 1
    FROM data_mapper
    WHERE referer_host = p_host

    UNION

    -- Recursive case: up to 3rd degree hosts
    SELECT CASE
               WHEN cte.depth % 2 = 1 THEN dm.destination_host
               ELSE dm.referer_host
               END,
           cte.depth + 1
    FROM data_mapper dm
             JOIN cte ON (
        (cte.depth % 2 = 1 AND cte.host = dm.referer_host) OR
        (cte.depth % 2 = 0 AND cte.host = dm.destination_host)
        )
    WHERE cte.depth < 4)
SELECT DISTINCT host
FROM cte
where host != '';
$$;

create or replace function get_referer_destination_pairs_within_four_degrees(p_host text)
    returns TABLE
            (
                referer_host     text,
                destination_host text
            )
    language sql
as
$$
WITH RECURSIVE cte(referer_host, destination_host, depth) AS (
    -- Base case: 1st degree hosts
    SELECT referer_host, destination_host, 1
    FROM data_mapper
    WHERE referer_host = p_host

    UNION

    -- Recursive case: up to 4th degree hosts
    SELECT CASE
               WHEN cte.depth % 2 = 1 THEN cte.destination_host
               ELSE cte.referer_host
               END,
           CASE
               WHEN cte.depth % 2 = 1 THEN dm.destination_host
               ELSE dm.referer_host
               END,
           cte.depth + 1
    FROM data_mapper dm
             JOIN cte ON (
        (cte.depth % 2 = 1 AND cte.destination_host = dm.referer_host) OR
        (cte.depth % 2 = 0 AND cte.referer_host = dm.destination_host)
        )
    WHERE cte.depth < 4)
SELECT DISTINCT referer_host, destination_host
FROM cte
where referer_host != ''
  and destination_host != ''
  and referer_host != destination_host;
$$;

create or replace function get_referer_destination_host_pairs_within_three_degrees(p_host text)
    returns TABLE
            (
                referer_host          text,
                destination_host      text,
                degrees_of_separation integer
            )
    language sql
as
$$
WITH RECURSIVE cte(referer_host, destination_host, depth) AS (
    -- Base case: 1st degree hosts
    SELECT referer_host, destination_host, 1
    FROM data_mapper
    WHERE referer_host = p_host
       OR destination_host = p_host

    UNION

    -- Recursive case: up to 3rd degree hosts
    SELECT dm.referer_host,
           dm.destination_host,
           cte.depth + 1
    FROM data_mapper dm
             JOIN cte ON (
        cte.destination_host = dm.referer_host OR cte.destination_host = dm.destination_host OR
        cte.referer_host = dm.referer_host OR cte.referer_host = dm.destination_host
        )
    WHERE cte.depth < 3)
SELECT DISTINCT referer_host, destination_host, depth as degrees_of_separation
FROM cte
where referer_host != ''
  and destination_host != ''
  and referer_host != destination_host;
$$;

create or replace function get_referer_destination_host_pairs_within_two_degrees(p_host text)
    returns TABLE
            (
                referer_host          text,
                destination_host      text,
                degrees_of_separation integer
            )
    language sql
as
$$
WITH RECURSIVE cte(referer_host, destination_host, depth) AS (
    -- Base case: 1st degree hosts
    SELECT referer_host, destination_host, 1
    FROM data_mapper
    WHERE referer_host = p_host
       OR destination_host = p_host

    UNION

    -- Recursive case: up to 3rd degree hosts
    SELECT dm.referer_host,
           dm.destination_host,
           cte.depth + 1
    FROM data_mapper dm
             JOIN cte ON (
        cte.destination_host = dm.referer_host OR cte.destination_host = dm.destination_host OR
        cte.referer_host = dm.referer_host OR cte.referer_host = dm.destination_host
        )
    WHERE cte.depth < 2)
SELECT DISTINCT referer_host, destination_host, depth as degrees_of_separation
FROM cte
where referer_host != ''
  and destination_host != ''
  and referer_host != destination_host;
$$;

create or replace function get_referer_destination_host_pairs_within_four_degrees(p_host text)
    returns TABLE
            (
                referer_host          text,
                destination_host      text,
                degrees_of_separation integer
            )
    language sql
as
$$
WITH RECURSIVE cte(referer_host, destination_host, depth) AS (
    -- Base case: 1st degree hosts
    SELECT referer_host, destination_host, 1
    FROM data_mapper
    WHERE referer_host = p_host
       OR destination_host = p_host

    UNION

    -- Recursive case: up to 3rd degree hosts
    SELECT dm.referer_host,
           dm.destination_host,
           cte.depth + 1
    FROM data_mapper dm
             JOIN cte ON (
        cte.destination_host = dm.referer_host OR cte.destination_host = dm.destination_host OR
        cte.referer_host = dm.referer_host OR cte.referer_host = dm.destination_host
        )
    WHERE cte.depth < 4)
SELECT DISTINCT referer_host, destination_host, depth as degrees_of_separation
FROM cte
where referer_host != ''
  and destination_host != ''
  and referer_host != destination_host;
$$;

create or replace function get_connected_hosts(p_hosts text[])
    returns TABLE
            (
                ref_host  text,
                dest_host text
            )
    language plpgsql
as
$$
BEGIN
    RETURN QUERY
        (
            -- When the given host is the referer_host
            SELECT referer_host     AS ref_host,
                   destination_host AS dest_host
            FROM data_mapper
            WHERE referer_host = ANY (p_hosts)
              AND destination_host <> ''
              AND referer_host <> destination_host)
        UNION
        (
            -- When the given host is the destination_host
            SELECT referer_host     AS ref_host,
                   destination_host AS dest_host
            FROM data_mapper
            WHERE destination_host = ANY (p_hosts)
              AND referer_host <> ''
              AND referer_host <> destination_host)
        ORDER BY ref_host, dest_host;
END;
$$;

create or replace function get_paths_and_connected_hosts(p_hosts text[])
    returns TABLE
            (
                source      text,
                destination text
            )
    language plpgsql
as
$$
BEGIN
    RETURN QUERY
        -- When the given host is the referer_host
        SELECT DISTINCT ON (source, destination) CASE
                                                     WHEN referer_host = ANY (p_hosts)
                                                         THEN referer_host || CASE WHEN referer_path = '/' THEN '' ELSE referer_path END
                                                     ELSE referer_host
                                                     END AS source,
                                                 CASE
                                                     WHEN destination_host = ANY (p_hosts) THEN destination_host || CASE
                                                                                                                        WHEN destination_path = '/'
                                                                                                                            THEN ''
                                                                                                                        ELSE destination_path END
                                                     ELSE destination_host
                                                     END AS destination
        FROM data_mapper
        WHERE referer_host = ANY (p_hosts)
           OR destination_host = ANY (p_hosts)
            AND referer_host != destination_host
            AND destination != ''
            AND source != ''
        ORDER BY source, destination;
END;
$$;

create or replace function get_classifications_for_mapper_data(p_url_hosts text[])
    returns TABLE
            (
                url_scheme text,
                url_host   text,
                url_path   text,
                class      integer
            )
    language plpgsql
as
$$
BEGIN
    RETURN QUERY
        SELECT c.url_scheme, c.url_host, c.url_path, c.class
        FROM classifications c
        WHERE c.url_host = ANY (p_url_hosts)
          AND (
            EXISTS (SELECT 1
                    FROM data_mapper dm
                    WHERE dm.referer_scheme = c.url_scheme
                      AND dm.referer_host = c.url_host
                      AND dm.referer_path = c.url_path) OR EXISTS (SELECT 1
                                                                   FROM data_mapper dm
                                                                   WHERE dm.destination_scheme = c.url_scheme
                                                                     AND dm.destination_host = c.url_host
                                                                     AND dm.destination_path = c.url_path)
            );
END;
$$;

create operator ~*@ (procedure = regexp_match_array_case_insensitive, leftarg = text[], rightarg = text);

create operator ~@ (procedure = regexp_match_array_case_sensitive, leftarg = text[], rightarg = text);

create operator !~*@ (procedure = regexp_not_match_array_case_insensitive, leftarg = text[], rightarg = text);

create operator !~@ (procedure = regexp_not_match_array_case_sensitive, leftarg = text[], rightarg = text);