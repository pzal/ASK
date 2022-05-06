# Development environment setup:

* Install docker
* Install python3.8
* Install postgres locally (required to build python lib even inside venv)
```bash
brew install postgres
```
* Create virtualenv for the project
```bash
python3.8 -m venv ./.iksde_bank_env
```
* Setup env vars
```bash
cp ./config.env.dist ./config.env
```
* Install requirements
```bash
source ./.iksde_bank_env/bin/activate
pip install -r ./requirements.txt
pip install -r ./requirements-dev.txt
```
* Create shared docker network:
```bash
docker network create shared-network
```


# Docker swarm deploy:

* Build frontend:
```bash
cd ../frontend
yarn build
```
* Build docker images:
```bash
make rebuild
```
* Create swarm:
```bash
docker swarm init
```
* Deploy service:
```bash
docker stack deploy -c docker-stack.yml iksde-bank
```


# Docker swarm stack management:

* Monitor the stack:
```bash
watch docker stack ps iksde-bank
```
* See api logs:
```bash
docker service logs iksde-bank_api --follow
```
* Remove the stack:
```bash
docker stack rm iksde-bank
```
