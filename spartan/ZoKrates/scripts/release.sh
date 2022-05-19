# Exit if any subcommand fails
set -e

# Get tag
TAG=$(cat ./zokrates_cli/Cargo.toml | grep '^version' | awk '{print $3}' | sed -e 's/"//g') && echo $TAG

# Use zokrates github bot
git config --global user.email $GH_USER

# Release on Dockerhub

## Build
docker build -t zokrates .

## Log into Dockerhub
echo $DOCKERHUB_PASS | docker login -u $DOCKERHUB_USER --password-stdin

## Release under `latest` tag
docker tag zokrates:latest zokrates/zokrates:latest
docker push zokrates/zokrates:latest
echo "Published zokrates/zokrates:latest"

## Release under $TAG tag
docker tag zokrates:latest zokrates/zokrates:$TAG
docker push zokrates/zokrates:$TAG
echo "Published zokrates/zokrates:$TAG"

# Release on Github
git tag $TAG
git push origin $TAG

# Publish book
MDBOOK_TAR="https://github.com/rust-lang-nursery/mdBook/releases/download/v0.2.1/mdbook-v0.2.1-x86_64-unknown-linux-gnu.tar.gz"

cd zokrates_book

## Install mdbook
wget -qO- $MDBOOK_TAR | tar xvz

## Build book
./mdbook build

## Deploy to github.io
git clone https://github.com/Zokrates/zokrates.github.io.git
git clone https://github.com/davisp/ghp-import.git
cd zokrates.github.io
../ghp-import/ghp_import.py -n -p -f -m "Documentation upload. Version:  $TAG" -b "master" -r https://zokratesbot:"$GH_TOKEN"@github.com/Zokrates/zokrates.github.io.git ../book
echo "Published book"

