setup:
	docker-compose run api python manage.py migrate
	docker-compose run api python manage.py collectstatic --clear --no-input
	docker-compose run api python manage.py populate_with_development_data

resetup:
	$(MAKE) clean
	$(MAKE) setup

makemigrations:
	docker-compose run api python manage.py makemigrations

recreate_migrations:
	find . -path "./*/migrations/*.py" -not -name "__init__.py" -not -path "*site-packages*" -delete || exit 1
	docker-compose run api python manage.py makemigrations

sp:
	docker-compose run api python manage.py shell_plus

migrate:
	docker-compose run api python manage.py migrate

clean:
	docker-compose down -v
	rm -rf uploads || true
	rm -rf static || true
	rm celerybeat-schedule || true
	rm celerybeat.pid || true

rebuild:
	docker-compose build

up:
	docker-compose up

up-elk:
	docker-compose -f elk/docker-compose.yml up

test:
	docker-compose run api python manage.py test
