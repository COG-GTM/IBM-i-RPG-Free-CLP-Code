-- Indexes --
drop index if exists custmast_name;
create index custmast_name on custmast(name);
drop index if exists custmast_city;
create index custmast_city on custmast(city);
drop index if exists custmast_state;
create index custmast_state on custmast(state);
