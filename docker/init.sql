CREATE DATABASE docker-orchestrator;
CREATE USER 'myuser'@'localhost' IDENTIFIED BY 'mysql';
GRANT ALL PRIVILEGES ON docker-orchestrator.* TO 'docker_api_user'@'localhost';
FLUSH PRIVILEGES;