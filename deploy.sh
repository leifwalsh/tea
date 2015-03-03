#!/bin/bash

rev=$(git rev-parse --short HEAD)

cd target/doc

git init
git config user.name "Leif Walsh"
git config user.email "leif.walsh@gmail.com"

git remote add upstream "https://$GH_TOKEN@github.com/leifwalsh/tea.git"
git fetch upstream && git reset upstream/gh-pages

touch .

git add -A .
git commit -m "rebuild pages at ${rev}"
git push -q upstream HEAD:gh-pages
