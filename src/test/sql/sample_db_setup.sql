create table if not exists color(friendly_name varchar(255) primary key, red int, green int, blue int);
delete from color;
insert into color(friendly_name, red, green, blue) values('cyan', 26, 242, 227);
insert into color(friendly_name, red, green, blue) values('yellow', 213, 242, 26);
insert into color(friendly_name, red, green, blue) values('pink', 242, 26, 184);