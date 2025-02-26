# actix start
ACTIX_PACKAGE=--package actix-blog-rs
ACTIX_DEPENDENCIES_WITH_FEATURES=actix-web \
 	actix-cors \
    serde_json \
	dotenvy \
	lazy_static

# actix end
# axum start
AXUM_PACKAGE=--package axum-blog-rs
AXUM_DEPENDENCIES_WITH_FEATURES=env_logger \
	dotenvy \
	lazy_static \
	axum \
	tokio=full

# axum end


GRPC_ACTIX_WITH_FEATURES=actix-web \
 	actix-cors \
    serde_json \
	env_logger \
	dotenvy \
	lazy_static \
	tonic \
	tokio=full \
	prost 



#  install start
install: install_grpc_actix
# SQLX-CLI
	@cargo install sqlx-cli

install_monorepo: install-actix install-axum
# SQLX-CLI
	@cargo install sqlx-cli


install_grpc_actix: 
	@echo 'grpc_actix dependencies starting to install.....'
	@for item in $(GRPC_ACTIX_WITH_FEATURES); do \
		dep_name=$$(echo $$item | cut -d'=' -f1); \
		features=$$(echo $$item | cut -d'=' -f2); \
		if [ -n "$$features" ] && [ "$$features" != "$$dep_name" ]; then \
			echo "Adding $$dep_name with features: $$features"; \
			cargo add $$dep_name --features $$features; \
		else \
			echo "Adding $$dep_name without features"; \
			cargo add $$dep_name; \
		fi; \
	done
	@echo 'actix dependencies installed successfully'
	
install-actix:
	@echo 'actix dependencies starting to install.....'
	@for item in $(ACTIX_DEPENDENCIES_WITH_FEATURES); do \
		dep_name=$$(echo $$item | cut -d'=' -f1); \
		features=$$(echo $$item | cut -d'=' -f2); \
		if [ -n "$$features" ] && [ "$$features" != "$$dep_name" ]; then \
			echo "Adding $$dep_name with features: $$features"; \
			cargo add $$dep_name --features $$features $(ACTIX_PACKAGE); \
		else \
			echo "Adding $$dep_name without features"; \
			cargo add $$dep_name $(ACTIX_PACKAGE); \
		fi; \
	done
	@echo 'actix dependencies installed successfully'


install-axum: 
	@echo 'axum dependencies starting to install.....'
	@for item in $(AXUM_DEPENDENCIES_WITH_FEATURES); do \
		dep_name=$$(echo $$item | cut -d'=' -f1); \
		features=$$(echo $$item | cut -d'=' -f2); \
		if [ -n "$$features" ] && [ "$$features" != "$$dep_name" ]; then \
			echo "Adding $$dep_name with features: $$features"; \
			cargo add $$dep_name --features $$features $(AXUM_PACKAGE); \
		else \
			echo "Adding $$dep_name without features"; \
			cargo add $$dep_name $(AXUM_PACKAGE); \
		fi; \
	done
	@echo 'axum dependencies installed successfully'

# install end


.PHONY: run-require-containers
run-require-containers: postgres-docker redis-docker

.PHONY: postgres-docker
postgres-docker: 
	@echo "Running..."
	@docker-compose -f docker-compose/services/docker-compose-postgres.yml up -d

.PHONY: redis-docker
redis-docker:
	@echo "Running..."
	@docker-compose -f docker-compose/services/docker-compose-redis.yml up -d

.PHONY: remove-all-containers
remove-docker-all-containers:
	@echo "Running..."
	@docker rm $$(docker ps -aq) -f

.PHONY: remove-docker-all-images
remove-docker-all-images:
	@echo "Running..."
	@docker rmi $$(docker images -aq) -f

create_migrations:
	sqlx migrate add -r init

migrate-up:
	sqlx migrate run

migrate-down:
	sqlx migrate revert


# build start 

build-actix: 
	@cargo build --package actix-blog-rs

build-axum: 
	@cargo build --package axum-blog-rs

# build end

# run start 

run-actix: 
	@cargo run --package actix-blog-rs

run-axum: 
	@cargo run --package axum-blog-rs

# run stop 



