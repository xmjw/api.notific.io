create user notific with login password 'development';

create database notific with owner notific; 

create table endpoints (
id char(8) primary key,
token char(8),
device_id varchar(36) unique,
device_type char(10),
device_token varchar(128),
created_at timestamp);

grant select, insert on endpoints to notific;

create table notifications (
id varchar(36) primary key,
endpoint_id char(8),
payload text,
encrypted boolean,
created_at timestamp);

grant select, insert, update on notifications to notific;
